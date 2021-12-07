package gogsym

import (
	"fmt"

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

	// check bounds
	if relAddr < entryAddr || relAddr > entryAddr+uint64(fnSize) {
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

	fmt.Printf("looking up %d\n", lineInfo.entry.FileIndex)

	path, err := g.GetFile(lineInfo.entry.FileIndex)
	if err != nil {
		path = ""
	}

	loc := SourceLocation{
		Name:   name,
		Line:   lineInfo.entry.Line,
		Offset: uint32(relAddr - entryAddr),
		File:   path,
	}

	lr.Locations = append(lr.Locations, loc)

	return lr, err
}

type InfoType uint32

const (
	InfoTypeEndOfList InfoType = 0
	InfoTypeLineTable InfoType = 1
	InfoTypeInline    InfoType = 2
)

type lineInfoResult struct {
	entry            LineEntry
	inlineDataOffset uint64
}

func (g Gsym) lookupLineInfo(c binarycursor.BinaryCursor, startAddr uint64, addr uint64) (lineInfoResult, error) {
	done := false

	result := lineInfoResult{}

	for done == false {
		infoType, err := c.ReadUint32()
		if err != nil {
			return result, err
		}

		infoLength, err := c.ReadUint32()
		if err != nil {
			return result, err
		}

		fmt.Printf("0x%x => 0x%x 0x%x\n", addr, infoType, infoLength)

		switch InfoType(infoType) {
		case InfoTypeEndOfList:
			done = true
		case InfoTypeLineTable:
			result.entry, err = g.lookupLineTable(&c, startAddr, addr)
			if err != nil {
				return result, err
			}
		case InfoTypeInline:
			fmt.Print("found inline info\n")
		}
	}

	return result, nil
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

func (g Gsym) lookupLineTable(c *binarycursor.BinaryCursor, startAddr uint64, addr uint64) (LineEntry, error) {
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

	fmt.Printf("line range is: %d\n", lineRange)
	done := false

	for done == false {
		op, err := c.ReadUint8()
		if err != nil {
			return entry, err
		}

		fmt.Printf("op: 0x%x\n", op)

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

		fmt.Printf("entry is now: 0x%x => %d:%d\n", entry.Address, entry.FileIndex, entry.Line)

		if nextEntry.Address > addr {
			return entry, nil
		}

		entry = nextEntry
	}

	// if we get to the end, return the last entry
	return entry, nil
}