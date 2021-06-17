package gogsym

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderParsing(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	assert.Equal(t, GSYM_MAGIC, g.Header.Magic)
	assert.Equal(t, uint16(0x0001), g.Header.Version)
	assert.Equal(t, uint8(0x02), g.Header.AddrOffSize)
	assert.Equal(t, uint8(0x10), g.Header.UUIDSize)
	assert.Equal(t, uint64(0x100000000), g.Header.BaseAddress)
	assert.Equal(t, uint32(0x00000008), g.Header.NumAddresses)
	assert.Equal(t, uint32(0x0000008c), g.Header.StrtabOffset)
	assert.Equal(t, uint32(0x000001de), g.Header.StrtabSize)
	assert.Equal(t, "6245042154203af087ca010fc8d6ceba", g.Header.UUIDString())

	assert.Equal(t, int64(48), g.Header.Size())
}

func TestGetAddressIndex(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	idx, err := g.GetTextRelativeAddressIndex(0x308b)
	assert.Equal(t, ErrAddressNotFound, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x308c)
	assert.Nil(t, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x308d)
	assert.Nil(t, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x30d4)
	assert.Nil(t, err)
	assert.Equal(t, 1, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x32b4)
	assert.Nil(t, err)
	assert.Equal(t, 7, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x32b5)
	assert.Nil(t, err)
	assert.Equal(t, 7, idx)
}

func TestGetAddressInfo(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	off, err := g.GetAddressInfoOffset(7)
	assert.Nil(t, err)
	assert.Equal(t, int64(0x410), off)
}

func TestLookupAddress(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	_, err = g.LookupTextRelativeAddress(0x32b3)
	if assert.Nil(t, err) == false {
		return
	}
}
