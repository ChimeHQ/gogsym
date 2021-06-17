package gogsym

import (
	"encoding/binary"
	"errors"
	"io"
)

type parser struct {
	r     io.ReaderAt
	order binary.ByteOrder
	buf8  []byte
	buf16 []byte
	buf32 []byte
	buf64 []byte
}

var ErrReadWrongSize = errors.New("Wrong size")

func newParser(r io.ReaderAt) parser {
	return parser{
		r:     r,
		order: binary.LittleEndian,
		buf8:  []byte{0x0},
		buf16: []byte{0x0, 0x0},
		buf32: []byte{0x0, 0x0, 0x0, 0x0},
		buf64: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	}
}

func (p parser) flipOrder() {
	switch p.order {
	case binary.BigEndian:
		p.order = binary.LittleEndian
	case binary.LittleEndian:
		p.order = binary.BigEndian
	}
}

func (p parser) readUint8(offset int64) (uint8, error) {
	i, err := p.r.ReadAt(p.buf8, offset)
	if err != nil {
		return 0, err
	}
	if i != 1 {
		return 0, ErrReadWrongSize
	}

	return uint8(p.buf8[0]), err
}

func (p parser) readUint16(offset int64) (uint16, error) {
	i, err := p.r.ReadAt(p.buf16, offset)
	if err != nil {
		return 0, err
	}
	if i != 2 {
		return 0, ErrReadWrongSize
	}

	return p.order.Uint16(p.buf16), nil
}

func (p parser) readUint32(offset int64) (uint32, error) {
	i, err := p.r.ReadAt(p.buf32, offset)
	if err != nil {
		return 0, err
	}
	if i != 4 {
		return 0, ErrReadWrongSize
	}

	return p.order.Uint32(p.buf32), nil
}

func (p parser) readUint64(offset int64) (uint64, error) {
	i, err := p.r.ReadAt(p.buf64, offset)
	if err != nil {
		return 0, err
	}
	if i != 8 {
		return 0, ErrReadWrongSize
	}

	return p.order.Uint64(p.buf64), nil
}

func (p parser) readNullTerminatedUTF8String(offset int64) (string, error) {
	data := []byte{}
	count := int64(0)

	for {
		n, err := p.r.ReadAt(p.buf8, offset+count)
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", ErrReadWrongSize
		}

		if p.buf8[0] == 0 {
			break
		}

		count += 1
		data = append(data, p.buf8[0])
	}

	return string(data), nil
}
