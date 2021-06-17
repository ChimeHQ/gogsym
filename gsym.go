package gogsym

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
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

type Address uint64

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

func newHeader(p parser) (Header, error) {
	h := Header{}

	var err error

	h.Magic, err = p.readUint32(0)
	if err != nil {
		return h, err
	}

	if h.Magic == GSYM_CIGAM {
		p.flipOrder()
	}

	h.Version, err = p.readUint16(4)
	if err != nil {
		return h, err
	}

	if h.Version != uint16(1) {
		return h, ErrUnsupportedVersion
	}

	h.AddrOffSize, err = p.readUint8(6)
	if err != nil {
		return h, err
	}

	h.UUIDSize, err = p.readUint8(7)
	if err != nil {
		return h, err
	}

	if h.UUIDSize > GSYM_MAX_UUID_SIZE {
		return h, ErrUUIDSizeOutOfRange
	}

	h.BaseAddress, err = p.readUint64(8)
	if err != nil {
		return h, err
	}

	h.NumAddresses, err = p.readUint32(16)
	if err != nil {
		return h, err
	}

	h.StrtabOffset, err = p.readUint32(20)
	if err != nil {
		return h, err
	}

	h.StrtabSize, err = p.readUint32(24)
	if err != nil {
		return h, err
	}

	n, err := p.r.ReadAt(h.UUID[0:h.UUIDSize], 28)
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
	parser parser
	Header Header
}

func NewGsymWithReader(r io.ReaderAt) (Gsym, error) {
	p := newParser(r)

	g := Gsym{
		parser: p,
		Header: Header{},
	}

	header, err := newHeader(p)
	if err != nil {
		return g, err
	}

	g.Header = header

	return g, nil
}

func (g Gsym) AddressTableOffset() int64 {
	return int64(g.Header.Size())
}

func (g Gsym) ReadAddressEntry(idx int) (uint64, error) {
	offset := int64(idx)*int64(g.Header.AddrOffSize) + g.AddressTableOffset()

	switch g.Header.AddrOffSize {
	case 1:
		v8, err := g.parser.readUint8(offset)

		return uint64(v8), err
	case 2:
		v16, err := g.parser.readUint16(offset)

		return uint64(v16), err
	case 4:
		v32, err := g.parser.readUint32(offset)

		return uint64(v32), err
	case 8:
		v64, err := g.parser.readUint64(offset)

		return uint64(v64), err
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

	value, err := g.parser.readUint32(offset)

	return int64(value), err
}

type LookupResult struct {
}

func (g Gsym) LookupTextRelativeAddress(addr uint64) (LookupResult, error) {
	lr := LookupResult{}

	addrIdx, err := g.GetTextRelativeAddressIndex(addr)
	if err != nil {
		return lr, err
	}

	addrInfoOffset, err := g.GetAddressInfoOffset(addrIdx)
	if err != nil {
		return lr, err
	}

	fmt.Printf("0x%x => %d, 0x%x\n", addr, addrIdx, addrInfoOffset)

	return lr, nil
}
