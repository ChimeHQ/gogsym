package gogsym

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadInlineAppGSYM(t *testing.T) {
	f, err := os.Open("testdata/inlineapp.gsym")
	defer f.Close()
	if assert.Nil(t, err) == false {
		return
	}

	g, err := NewGsym(f)
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
}