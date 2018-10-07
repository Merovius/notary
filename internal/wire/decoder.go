package wire

import (
	"encoding/binary"
	"errors"
	"runtime/debug"
	"time"
)

var (
	errMsgTooShort      = errors.New("message too short")
	errTooManyFields    = errors.New("too many fields")
	errFieldMissing     = errors.New("missing field")
	errInvalidOffset    = errors.New("invalid offset")
	errUnsortedTags     = errors.New("tags not sorted")
	errInvalidMessage   = errors.New("invalid message")
	errInvalidField     = errors.New("invalid field")
	errInvalidTimestamp = errors.New("invalid timestamp")
	errInvalidDuration  = errors.New("invalid duration")
)

type DecodeState struct {
	hdr  []byte
	body []byte
	err  *error
	i    uint32
	n    uint32
}

var sentinel = new(int8)

func Decode(msg []byte, f func(st *DecodeState)) (err error) {
	defer func() {
		if v := recover(); v == sentinel {
			debug.PrintStack()
		} else if v != nil {
			panic(v)
		}
	}()
	st := &DecodeState{err: &err}
	st.SetMessage(msg)
	f(st)
	return nil
}

func (d *DecodeState) Abort(e error) {
	if e != nil {
		*d.err = e
		panic(sentinel)
	}
}

func (d *DecodeState) SetMessage(b []byte) {
	if len(b) < 4 {
		d.Abort(errMsgTooShort)
	}
	d.n = binary.LittleEndian.Uint32(b)
	if uint32(len(b))/8 < d.n {
		d.Abort(errMsgTooShort)
	}
	var (
		t = binary.LittleEndian.Uint32(b[4*d.n:])
		o uint32
	)
	for i := uint32(1); i < d.n; i++ {
		o2, t2 := binary.LittleEndian.Uint32(b[i*4:]), binary.LittleEndian.Uint32(b[d.n*4+i*4:])
		if t2 <= t || o2 < o || o2 >= uint32(len(b)) {
			d.Abort(errInvalidMessage)
		}
		t, o = t2, o2
	}
	d.hdr = b[0 : 8*d.n : 8*d.n]
	d.body = b[8*d.n:]
}

func (d *DecodeState) Bytes(t Tag, p *[]byte) {
	for ; d.i < d.n; d.i++ {
		tag := Tag(binary.LittleEndian.Uint32(d.hdr[d.n*4+d.i*4:]))
		if tag > t {
			continue
		}
		if tag < t {
			d.Abort(errFieldMissing)
		}
		start, end := uint32(0), uint32(len(d.body))
		if d.i > 0 {
			start = binary.LittleEndian.Uint32(d.hdr[d.i*4:])
		}
		if d.i+1 < d.n {
			end = binary.LittleEndian.Uint32(d.hdr[(d.i+1)*4:])
		}
		if end < start || ((end-start)%4 != 0) {
			d.Abort(errInvalidField)
		}
		*p = d.body[start:end]
		d.i++
		return
	}
	d.Abort(errFieldMissing)
}

func (d *DecodeState) Uint32(t Tag, p *uint32) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 4 {
		d.Abort(errInvalidField)
	}
	*p = binary.LittleEndian.Uint32(buf)
}

func (d *DecodeState) Uint64(t Tag, p *uint64) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 8 {
		d.Abort(errInvalidField)
	}
	*p = binary.LittleEndian.Uint64(buf)
}

func (d *DecodeState) Bytes32(t Tag, p *[32]byte) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 32 {
		d.Abort(errInvalidField)
	}
	copy((*p)[:], buf)
}

func (d *DecodeState) Bytes64(t Tag, p *[64]byte) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 64 {
		d.Abort(errInvalidField)
	}
	copy((*p)[:], buf)
}

func (d *DecodeState) Message(t Tag, raw *[]byte, f func(*DecodeState)) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) < 4 {
		d.Abort(errInvalidMessage)
	}
	st := &DecodeState{err: d.err}
	st.SetMessage(buf)
	f(st)
	*raw = buf
}

func (d *DecodeState) Time(t Tag, p *time.Time) {
	var v uint64
	d.Uint64(t, &v)
	if v&(1<<63) != 0 {
		d.Abort(errInvalidTimestamp)
	}
	*p = time.Unix(int64(v)/1e6, (int64(v)%1e6)*1e3)
}

func (d *DecodeState) Duration(t Tag, p *time.Duration) {
	var v uint32
	d.Uint32(t, &v)
	*p = time.Duration(v) * time.Microsecond
	if time.Duration(v) != *p/time.Microsecond {
		d.Abort(errInvalidDuration)
	}
}
