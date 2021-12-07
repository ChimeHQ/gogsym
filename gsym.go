package gogsym

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/chimehq/binarycursor"
)

const GSYM_MAGIC uint32 = 0x4753594d
const GSYM_CIGAM uint32 = 0x4d595347
const GSYM_MAX_UUID_SIZE = 20
const GSYM_HEADER_SIZE = 28 + GSYM_MAX_UUID_SIZE

var ErrUnsupportedVersion = errors.New("Unsupported Version")
var ErrAddressOutOfRange = errors.New("Address out of range")
var ErrUUIDSizeOutOfRange = errors.New("UUID size out of range")
var ErrAddressSizeOutOfrange = errors.New("Address size out of range")
var ErrAddressNotFound = errors.New("Address not found")

type Header struct {
	Magic        uint32
	Version      uint16
	AddrOffSize  uint8
	UUIDSize     uint8
	BaseAddress  uint64
	NumAddresses uint32
	StrtabOffset uint32
	StrtabSize   uint32
	UUID         [GSYM_MAX_UUID_SIZE]byte
}

func (h Header) Size() int64 {
	return int64(GSYM_HEADER_SIZE)
}

func newHeader(bc binarycursor.BinaryCursor) (Header, error) {
	h := Header{}

	var err error

	h.Magic, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	if h.Magic == GSYM_CIGAM {
		bc.FlipOrder()
	}

	h.Version, err = bc.ReadUint16()
	if err != nil {
		return h, err
	}

	if h.Version != uint16(1) {
		return h, ErrUnsupportedVersion
	}

	h.AddrOffSize, err = bc.ReadUint8()
	if err != nil {
		return h, err
	}

	h.UUIDSize, err = bc.ReadUint8()
	if err != nil {
		return h, err
	}

	if h.UUIDSize > GSYM_MAX_UUID_SIZE {
		return h, ErrUUIDSizeOutOfRange
	}

	h.BaseAddress, err = bc.ReadUint64()
	if err != nil {
		return h, err
	}

	h.NumAddresses, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	h.StrtabOffset, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	h.StrtabSize, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	n, err := bc.Read(h.UUID[0:h.UUIDSize])
	if n != int(h.UUIDSize) {
		return h, fmt.Errorf("Expected %d UUIDS bytes, got %d", h.UUIDSize, n)
	}

	return h, nil
}

func (h Header) UUIDBytes() []byte {
	return h.UUID[0:h.UUIDSize]
}

func (h Header) UUIDString() string {
	return hex.EncodeToString(h.UUIDBytes())
}

type Gsym struct {
	readerAt io.ReaderAt
	cursor   binarycursor.BinaryCursor
	Header   Header
}

func NewGsymWithReader(r io.ReaderAt) (Gsym, error) {
	bc := binarycursor.NewBinaryReaderAtCursor(r, 0)

	g := Gsym{
		readerAt: r,
		cursor:   bc,
		Header:   Header{},
	}

	header, err := newHeader(bc)
	if err != nil {
		return g, err
	}

	g.Header = header

	return g, nil
}

func (g Gsym) cursorAt(offset int64) binarycursor.BinaryCursor {
	c := binarycursor.NewBinaryReaderAtCursor(g.readerAt, offset)

	c.SetOrder(g.cursor.Order())

	return c
}

func (g Gsym) AddressTableOffset() int64 {
	return int64(g.Header.Size())
}

func (g Gsym) ReadAddressEntry(idx int) (uint64, error) {
	offset := int64(idx)*int64(g.Header.AddrOffSize) + g.AddressTableOffset()
	cursor := g.cursorAt(offset)

	switch g.Header.AddrOffSize {
	case 1:
		v8, err := cursor.ReadUint8()

		return uint64(v8), err
	case 2:
		v16, err := cursor.ReadUint16()

		return uint64(v16), err
	case 4:
		v32, err := cursor.ReadUint32()

		return uint64(v32), err
	case 8:
		return cursor.ReadUint64()
	}

	return uint64(0), ErrAddressSizeOutOfrange
}

func (g Gsym) GetTextRelativeAddressIndex(addr uint64) (int, error) {
	return g.GetAddressIndex(addr + g.Header.BaseAddress)
}

func (g Gsym) GetAddressIndex(addr uint64) (int, error) {
	if addr < g.Header.BaseAddress {
		return 0, ErrAddressOutOfRange
	}

	relAddr := addr - g.Header.BaseAddress
	count := int(g.Header.NumAddresses)

	idx := sort.Search(count, func(i int) bool {
		entryAddr, _ := g.ReadAddressEntry(i)

		return entryAddr >= relAddr
	})

	entryAddr, err := g.ReadAddressEntry(idx)
	if err != nil {
		return 0, err
	}

	if idx == 0 && relAddr < entryAddr {
		return 0, ErrAddressNotFound
	}

	if idx == count || relAddr < entryAddr {
		idx -= 1
	}

	return idx, nil
}

func (g Gsym) AddressInfoTableOffset() int64 {
	addrTableSize := int64(g.Header.NumAddresses) * int64(g.Header.AddrOffSize)

	return g.AddressTableOffset() + addrTableSize
}

func (g Gsym) GetAddressInfoOffset(index int) (int64, error) {
	offset := g.AddressInfoTableOffset() + int64(index*4)

	c := g.cursorAt(offset)

	value, err := c.ReadUint32()

	return int64(value), err
}

func (g Gsym) GetString(offset int64) (string, error) {
	strOffset := int64(g.Header.StrtabOffset) + offset

	c := g.cursorAt(strOffset)

	return c.ReadNullTerminatedUTF8String()
}

type FileEntry struct {
	DirStrOffset  uint32
	BaseStrOffset uint32
}

func (g Gsym) GetFileEntry(index uint32) (FileEntry, error) {
	offset := g.AddressInfoTableOffset() + int64(g.Header.NumAddresses*4)

	// offset: uint32 count
	// offset + 4: uint32(0), uint32(0)

	// and, every entry is 2 uint32s

	offset += 4 + int64(index)*4*2

	c := g.cursorAt(offset)

	entry := FileEntry{}
	var err error = nil

	entry.DirStrOffset, err = c.ReadUint32()
	if err != nil {
		return entry, err
	}

	entry.BaseStrOffset, err = c.ReadUint32()

	return entry, err
}

func (g Gsym) GetFile(index uint32) (string, error) {
	if index == 0 {
		return "", nil
	}

	entry, err := g.GetFileEntry(index)
	if err != nil {
		return "", err
	}

	dir, err := g.GetString(int64(entry.DirStrOffset))
	if err != nil {
		return "", err
	}

	base, err := g.GetString(int64(entry.BaseStrOffset))
	if err != nil {
		return "", err
	}

	return dir + "/" + base, nil
}