package wire

import (
	"encoding/binary"
	"time"
)

type EncodeState struct {
	msg []byte

	n    uint32
	i    uint32
	t    Tag
	hdr  []byte
	body []byte
}

func Encode(f func(st *EncodeState)) []byte {
	msg := make([]byte, 1024)
	st := &EncodeState{msg: msg}
	f(st)
	return st.msg[:st.Length()]
}

func (e *EncodeState) NTags(n uint32) {
	binary.LittleEndian.PutUint32(e.msg, n)
	e.hdr = e.msg[0 : 8*n : 8*n]
	e.body = e.msg[8*n : 8*n : len(e.msg)]
	e.n = n
	e.i = 0
}

func (e *EncodeState) Length() int {
	return 8*int(e.n) + len(e.body)
}

func (e *EncodeState) Bytes(t Tag, n int) []byte {
	if e.t >= t {
		panic("tags not written in ascending order")
	}
	e.t = t
	if e.i > 0 {
		binary.LittleEndian.PutUint32(e.hdr[4*e.i:], uint32(len(e.body)))
	}
	binary.LittleEndian.PutUint32(e.hdr[4*e.n+4*e.i:], uint32(t))
	e.i++

	buf := e.body[len(e.body) : len(e.body)+n]
	e.body = e.body[:len(e.body)+n]
	return buf
}

func (e *EncodeState) Bytes32(t Tag, p [32]byte) {
	buf := e.Bytes(t, 32)
	copy(buf, p[:])
}

func (e *EncodeState) Bytes64(t Tag, p [64]byte) {
	buf := e.Bytes(t, 64)
	copy(buf, p[:])
}

func (e *EncodeState) Uint32(t Tag, v uint32) {
	buf := e.Bytes(t, 4)
	binary.LittleEndian.PutUint32(buf, v)
}

func (e *EncodeState) Uint64(t Tag, v uint64) {
	buf := e.Bytes(t, 8)
	binary.LittleEndian.PutUint64(buf, v)
}

func (e *EncodeState) Message(t Tag, f func(*EncodeState)) {
	st := &EncodeState{msg: e.body}
	f(st)
	e.Bytes(t, e.Length())
}

func (e *EncodeState) Time(t Tag, v time.Time) {
	e.Uint64(t, uint64(v.UnixNano()/1000))
}

func (e *EncodeState) Duration(t Tag, v time.Duration) {
	e.Uint32(t, uint32(v/time.Microsecond))
}
