package wire

import (
	"encoding/binary"
	"time"
)

// EncodeState holds state about the encoding process. It is not supposed to be
// used directly - call Encode instead.
type EncodeState struct {
	msg []byte

	n    uint32
	i    uint32
	t    Tag
	hdr  []byte
	body []byte
}

// Encode runs f to encode a message. f can use the EncodeState to emit wanted
// fields.
func Encode(f func(st *EncodeState)) []byte {
	msg := make([]byte, 1024)
	st := &EncodeState{msg: msg}
	f(st)
	return st.msg[:st.Length()]
}

// NTags sets the number of tags of the message. It must be called before any
// other methods of EncodeState.
func (e *EncodeState) NTags(n uint32) {
	if n == 0 {
		e.hdr = e.msg[:4]
		e.body = e.msg[4:4:len(e.msg)]
	} else {
		binary.LittleEndian.PutUint32(e.msg, n)
		e.hdr = e.msg[0 : 8*n : 8*n]
		e.body = e.msg[8*n : 8*n : len(e.msg)]
	}
	e.n = n
	e.i = 0
}

// Length returns the length of the message, as far as encoded so far.
func (e *EncodeState) Length() int {
	return len(e.hdr) + len(e.body)
}

// Bytes emits a field with tag t and length n, which must be divisible by 4.
// It returns a slice that the data should be written to.
func (e *EncodeState) Bytes(t Tag, n int) []byte {
	if n < 0 || (n%4 != 0) {
		panic("length of field not multiple of 4")
	}
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

// Bytes32 emits a field with tag t and value v.
func (e *EncodeState) Bytes32(t Tag, v [32]byte) {
	buf := e.Bytes(t, 32)
	copy(buf, v[:])
}

// Bytes64 emits a field with tag t and value v.
func (e *EncodeState) Bytes64(t Tag, v [64]byte) {
	buf := e.Bytes(t, 64)
	copy(buf, v[:])
}

// Uint32 emits a field with tag t and value v.
func (e *EncodeState) Uint32(t Tag, v uint32) {
	buf := e.Bytes(t, 4)
	binary.LittleEndian.PutUint32(buf, v)
}

// Uint64 emits a field with tag t and value v.
func (e *EncodeState) Uint64(t Tag, v uint64) {
	buf := e.Bytes(t, 8)
	binary.LittleEndian.PutUint64(buf, v)
}

// Message emits a field with tag t and calls f to encode a submessage.
func (e *EncodeState) Message(t Tag, f func(*EncodeState)) {
	st := &EncodeState{msg: e.body}
	f(st)
	e.Bytes(t, e.Length())
}

// Time emits a field with tag t and value v.
func (e *EncodeState) Time(t Tag, v time.Time) {
	e.Uint64(t, uint64(v.UnixNano()/1000))
}

// Duration emits a field with tag t and value v.
func (e *EncodeState) Duration(t Tag, v time.Duration) {
	e.Uint32(t, uint32(v/time.Microsecond))
}
