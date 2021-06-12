package gogsym

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
)

const GSYM_MAGIC uint32 = 0x4753594d
const GSYM_CIGAM uint32 = 0x4d595347
const GSYM_MAX_UUID_SIZE = 20

var ErrUnsupportedVersion = errors.New("Unsupported Version")

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

func (h Header) UUIDBytes() []byte {
	return h.UUID[0:h.UUIDSize]
}

func (h Header) UUIDString() string {
	return hex.EncodeToString(h.UUIDBytes())
}

type Gsym struct {
	order  binary.ByteOrder
	Header Header
}

func NewGsym(r io.Reader) (Gsym, error) {
	g := Gsym{
		order:  binary.LittleEndian,
		Header: Header{},
	}

	err := binary.Read(r, g.order, &g.Header.Magic)
	if err != nil {
		return g, err
	}

	if g.Header.Magic == GSYM_CIGAM {
		g.order = binary.BigEndian
	}

	err = binary.Read(r, g.order, &g.Header.Version)
	if err != nil {
		return g, err
	}

	if g.Header.Version != uint16(1) {
		return g, ErrUnsupportedVersion
	}

	err = binary.Read(r, g.order, &g.Header.AddrOffSize)
	if err != nil {
		return g, err
	}

	err = binary.Read(r, g.order, &g.Header.UUIDSize)
	if err != nil {
		return g, err
	}

	err = binary.Read(r, g.order, &g.Header.BaseAddress)
	if err != nil {
		return g, err
	}

	err = binary.Read(r, g.order, &g.Header.NumAddresses)
	if err != nil {
		return g, err
	}

	err = binary.Read(r, g.order, &g.Header.StrtabOffset)
	if err != nil {
		return g, err
	}

	err = binary.Read(r, g.order, &g.Header.StrtabSize)
	if err != nil {
		return g, err
	}

	for i := 0; i < int(g.Header.UUIDSize); i++ {
		err = binary.Read(r, g.order, &g.Header.UUID[i])
		if err != nil {
			return g, err
		}
	}

	return g, nil
}
