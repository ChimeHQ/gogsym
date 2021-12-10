package gogsym

import (
	"github.com/chimehq/binarycursor"
)

type SourceLocation struct {
	Name   string
	File   string
	Line   uint32
	Offset uint32
}

type LookupResult struct {
	Address   uint64
	StartAddr uint64
	Size      uint64
	Name      string
	Locations []SourceLocation
}

func (g Gsym) LookupAddress(addr uint64) (LookupResult, error) {
	return g.LookupTextRelativeAddress(addr - g.Header.BaseAddress)
}

func (g Gsym) LookupTextRelativeAddress(relAddr uint64) (LookupResult, error) {
	lr := LookupResult{
		Address: relAddr,
	}

	addrIdx, err := g.GetTextRelativeAddressIndex(relAddr)
	if err != nil {
		return lr, err
	}

	entryAddr, err := g.ReadAddressEntry(addrIdx)
	if err != nil {
		return lr, err
	}

	lr.StartAddr = entryAddr

	addrInfoOffset, err := g.GetAddressInfoOffset(addrIdx)
	if err != nil {
		return lr, err
	}

	c := g.cursorAt(addrInfoOffset)

	fnSize, err := c.ReadUint32()
	if err != nil {
		return lr, err
	}

	lr.Size = uint64(fnSize)

	// check bounds, but only if the function has non-zero size
	notContained := relAddr < entryAddr || relAddr > entryAddr+uint64(fnSize)
	if notContained && fnSize > 0 {
		return lr, ErrAddressNotFound
	}

	fnNameOffset, err := c.ReadUint32()
	if err != nil {
		return lr, err
	}

	name, err := g.GetString(int64(fnNameOffset))
	if err != nil {
		return lr, err
	}

	lr.Name = name

	lineInfo, err := g.lookupLineInfo(c, entryAddr, relAddr)
	if err != nil {
		return lr, err
	}

	path, err := g.GetFile(lineInfo.entry.FileIndex)
	if err != nil {
		path = ""
	}

	entryLoc := SourceLocation{
		Name:   name,
		Line:   lineInfo.entry.Line,
		Offset: uint32(relAddr - entryAddr),
		File:   path,
	}

	lr.Locations = []SourceLocation{entryLoc}

	inlineLocs, err := g.locationsForInlineInfo(lineInfo.inline, relAddr)
	if err != nil {
		return lr, err
	}

	if len(inlineLocs) == 0 {
		return lr, err
	}

	lr.Locations = []SourceLocation{}

	// ok, this is really annoying. The inline info
	// modifies the previous information. So, we have
	// to keep track and change as we go. Also, of course,
	// the array is in the reverse order.
	for i := len(inlineLocs) - 1; i >= 0; i-- {
		loc := inlineLocs[i]
		adjustedLoc := loc

		adjustedLoc.Line = entryLoc.Line
		adjustedLoc.File = entryLoc.File

		entryLoc = loc

		lr.Locations = append(lr.Locations, adjustedLoc)
	}

	return lr, err
}

type InfoType uint32

const (
	InfoTypeEndOfList InfoType = 0
	InfoTypeLineTable InfoType = 1
	InfoTypeInline    InfoType = 2
)

type lineInfoResult struct {
	entry  LineEntry
	inline inlineInfo
}

func (g Gsym) lookupLineInfo(c binarycursor.BinaryCursor, startAddr uint64, addr uint64) (lineInfoResult, error) {
	done := false

	result := lineInfoResult{}

	for done == false {
		infoType, err := c.ReadUint32()
		if err != nil {
			return result, err
		}

		_, err = c.ReadUint32()
		if err != nil {
			return result, err
		}

		switch InfoType(infoType) {
		case InfoTypeEndOfList:
			done = true
		case InfoTypeLineTable:
			result.entry, err = lookupLineTable(&c, startAddr, addr)
			if err != nil {
				return result, err
			}
		case InfoTypeInline:
			result.inline, err = decodeInlineInfo(&c, startAddr)
			if err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

func (g Gsym) locationsForInlineInfo(info inlineInfo, addr uint64) ([]SourceLocation, error) {
	locations := []SourceLocation{}

	if info.Contains(addr) == false {
		return locations, nil
	}

	name, err := g.GetString(int64(info.NameOffset))
	if err != nil {
		return locations, err
	}

	file, err := g.GetFile(info.FileIndex)
	if err != nil {
		return locations, err
	}

	loc := SourceLocation{
		Name:   name,
		File:   file,
		Line:   info.Line,
		Offset: uint32(addr - info.Ranges[0].Start),
	}

	locations = append(locations, loc)

	for _, child := range info.Children {
		sublocs, err := g.locationsForInlineInfo(child, addr)
		if err != nil {
			return locations, err
		}

		locations = append(locations, sublocs...)
	}

	return locations, nil
}

type LineEntry struct {
	Address   uint64
	FileIndex uint32
	Line      uint32
}

type LineTableOpCode uint8

const (
	LineTableOpEndSequence  LineTableOpCode = 0x00
	LineTableOpSetFile      LineTableOpCode = 0x01
	LineTableOpAdvancePC    LineTableOpCode = 0x02
	LineTableOpAdvanceLine  LineTableOpCode = 0x03
	LineTableOpFirstSpecial LineTableOpCode = 0x04
)

func lookupLineTable(c *binarycursor.BinaryCursor, startAddr uint64, addr uint64) (LineEntry, error) {
	entry := LineEntry{
		Address: startAddr,
	}

	minDelta, err := c.ReadSleb128()
	if err != nil {
		return LineEntry{}, err
	}

	maxDelta, err := c.ReadSleb128()
	if err != nil {
		return LineEntry{}, err
	}

	lineRange := maxDelta - minDelta + 1
	firstLine, err := c.ReadUleb128()
	if err != nil {
		return LineEntry{}, err
	}

	entry.FileIndex = 1
	entry.Line = uint32(firstLine)

	nextEntry := entry

	done := false

	for done == false {
		op, err := c.ReadUint8()
		if err != nil {
			return entry, err
		}

		switch LineTableOpCode(op) {
		case LineTableOpEndSequence:
			done = true
		case LineTableOpSetFile:
			idx, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.FileIndex = uint32(idx)
		case LineTableOpAdvancePC:
			addrDelta, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.Address += addrDelta
		case LineTableOpAdvanceLine:
			lineDelta, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.Line += uint32(lineDelta)
		default:
			// op contains both address and line increment
			adjusted := op - uint8(LineTableOpFirstSpecial)
			lineDelta := minDelta + (int64(adjusted) % lineRange)
			addrDelta := int64(adjusted) / lineRange

			nextEntry.Line += uint32(lineDelta)
			nextEntry.Address += uint64(addrDelta)
		}

		if nextEntry.Address > addr {
			return entry, nil
		}

		entry = nextEntry
	}

	// if we get to the end, return the last entry
	return entry, nil
}

type addressRange struct {
	Start uint64
	Size  uint64
}

func (r addressRange) End() uint64 {
	return r.Start + r.Size
}

func decodeAddressRanges(c *binarycursor.BinaryCursor, baseAddr uint64) ([]addressRange, error) {
	ranges := []addressRange{}

	length, err := c.ReadUleb128()
	if err != nil {
		return ranges, err
	}

	for i := 0; i < int(length); i++ {
		r := addressRange{}

		v, err := c.ReadUleb128()
		if err != nil {
			return ranges, err
		}

		r.Start = v + baseAddr

		v, err = c.ReadUleb128()
		if err != nil {
			return ranges, err
		}

		r.Size = v

		ranges = append(ranges, r)
	}

	return ranges, nil
}

type inlineInfo struct {
	NameOffset uint32
	FileIndex  uint32
	Line       uint32
	Offset     uint64
	Ranges     []addressRange
	Children   []inlineInfo
}

func (i inlineInfo) Ending() bool {
	// the tree terminates with empty ranges
	return len(i.Ranges) == 0
}

func (i inlineInfo) Contains(addr uint64) bool {
	if len(i.Ranges) == 0 {
		return false
	}

	for _, r := range i.Ranges {
		if addr >= r.Start && addr <= r.End() {
			return true
		}
	}

	return false
}

func decodeInlineInfo(c *binarycursor.BinaryCursor, startAddr uint64) (inlineInfo, error) {
	info := inlineInfo{}

	ranges, err := decodeAddressRanges(c, startAddr)
	if err != nil {
		return info, err
	}

	info.Ranges = ranges

	if info.Ending() {
		return info, nil
	}

	hasChildren, err := c.ReadUint8()
	if err != nil {
		return info, err
	}

	nameStrOffset, err := c.ReadUint32()
	if err != nil {
		return info, err
	}

	info.NameOffset = nameStrOffset

	fileIndex, err := c.ReadUleb128()
	if err != nil {
		return info, err
	}

	info.FileIndex = uint32(fileIndex)

	line, err := c.ReadUleb128()
	if err != nil {
		return info, err
	}

	info.Line = uint32(line)

	childBaseAddr := ranges[0].Start // always relative to the parent address
	for hasChildren == 1 {
		child, err := decodeInlineInfo(c, childBaseAddr)
		if err != nil {
			return info, err
		}

		if child.Ending() {
			break
		}

		info.Children = append(info.Children, child)
	}

	return info, nil
}