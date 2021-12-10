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

	lr, err := g.LookupTextRelativeAddress(0x3177)
	if assert.Nil(t, err) == false {
		return
	}

	assert.Equal(t, uint64(0x3177), lr.Address)
	assert.Equal(t, uint64(0x314c), lr.StartAddr)
	assert.Equal(t, uint64(0x38), lr.Size)
	assert.Equal(t, "main", lr.Name)

	if assert.Equal(t, 1, len(lr.Locations)) == false {
		return
	}

	assert.Equal(t, "main", lr.Locations[0].Name)
	assert.Equal(t, uint32(14), lr.Locations[0].Line)
	assert.Equal(t, "/Users/matt/Desktop/InlineTest/InlineTest/main.m", lr.Locations[0].File)
	assert.Equal(t, uint32(43), lr.Locations[0].Offset)
}

func TestLookupAddressWithInlineInfo(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	lr, err := g.LookupTextRelativeAddress(0x32b3)
	if assert.Nil(t, err) == false {
		return
	}

	assert.Equal(t, uint64(0x32b3), lr.Address)
	assert.Equal(t, uint64(0x3274), lr.StartAddr)
	assert.Equal(t, uint64(0x40), lr.Size)
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", lr.Name)

	if assert.Equal(t, 3, len(lr.Locations)) == false {
		return
	}

	loc := lr.Locations[0]
	assert.Equal(t, "functionB", loc.Name)
	assert.Equal(t, uint32(14), loc.Line)
	assert.Equal(t, "/Users/matt/Desktop/InlineTest/InlineTest/AppDelegate.m", loc.File)
	assert.Equal(t, uint32(31), loc.Offset)

	loc = lr.Locations[1]
	assert.Equal(t, "functionA", loc.Name)
	assert.Equal(t, uint32(18), loc.Line)
	assert.Equal(t, "/Users/matt/Desktop/InlineTest/InlineTest/AppDelegate.m", loc.File)
	assert.Equal(t, uint32(31), loc.Offset)

	loc = lr.Locations[2]
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", loc.Name)
	assert.Equal(t, uint32(33), loc.Line)
	assert.Equal(t, "/Users/matt/Desktop/InlineTest/InlineTest/AppDelegate.m", loc.File)
	assert.Equal(t, uint32(63), loc.Offset)
}

func TestLookupAddressInFunctionWithInlineInfo(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	lr, err := g.LookupTextRelativeAddress(0x3291)
	if assert.Nil(t, err) == false {
		return
	}

	assert.Equal(t, uint64(0x3291), lr.Address)
	assert.Equal(t, uint64(0x3274), lr.StartAddr)
	assert.Equal(t, uint64(0x40), lr.Size)
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", lr.Name)

	if assert.Equal(t, 1, len(lr.Locations)) == false {
		return
	}

	loc := lr.Locations[0]
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", loc.Name)
	assert.Equal(t, uint32(31), loc.Line)
	assert.Equal(t, "/Users/matt/Desktop/InlineTest/InlineTest/AppDelegate.m", loc.File)
	assert.Equal(t, uint32(29), loc.Offset)
}

func TestLookupAddressInGSYMWithoutLineTables(t *testing.T) {
	f, err := os.Open("testdata/CFNetwork.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsymWithReader(f)
	if assert.Nil(t, err) == false {
		return
	}

	assert.Equal(t, uint64(0x180a4e000), g.Header.BaseAddress)
	assert.Equal(t, "9c2d6e302482364380a345930c02edc0", g.Header.UUIDString())

	// inside CFURLRequestCreate
	lr, err := g.LookupAddress(0x0000000180ab303e)
	if assert.Nil(t, err) == false {
		return
	}

	if assert.Equal(t, 1, len(lr.Locations)) == false {
		return
	}

	loc := lr.Locations[0]
	assert.Equal(t, "CFURLRequestCreate", loc.Name)
	assert.Equal(t, uint32(0), loc.Line)
	assert.Equal(t, "", loc.File)
	assert.Equal(t, uint32(2), loc.Offset)
}
