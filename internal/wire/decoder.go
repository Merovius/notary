// Copyright 2018 Axel Wagner
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
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

// DecodeState holds state about the decoding process. It is not supposed to be
// used directly - call Decode instead.
type DecodeState struct {
	hdr  []byte
	body []byte
	err  *error
	i    uint32
	n    uint32
}

var sentinel = new(int8)

// Decode runs f to decode msg. f can use the passed DecodeState to extract the
// wanted fields.
func Decode(msg []byte, f func(st *DecodeState)) (err error) {
	defer func() {
		if v := recover(); v != nil && v != sentinel {
			panic(v)
		}
	}()
	st := &DecodeState{err: &err}
	st.SetMessage(msg)
	f(st)
	return nil
}

// Abort aborts the coding process with the given error.
func (d *DecodeState) Abort(e error) {
	if e != nil {
		*d.err = e
		panic(sentinel)
	}
}

// SetMessage validates the message header of msg and starts decoding.
func (d *DecodeState) SetMessage(msg []byte) {
	if len(msg) < 4 {
		d.Abort(errMsgTooShort)
	}
	d.n = binary.LittleEndian.Uint32(msg)
	if uint32(len(msg))/8 < d.n {
		d.Abort(errMsgTooShort)
	}
	var (
		t = binary.LittleEndian.Uint32(msg[4*d.n:])
		o uint32
	)
	for i := uint32(1); i < d.n; i++ {
		o2, t2 := binary.LittleEndian.Uint32(msg[i*4:]), binary.LittleEndian.Uint32(msg[d.n*4+i*4:])
		if t2 <= t || o2 < o || o2 >= uint32(len(msg)) {
			d.Abort(errInvalidMessage)
		}
		t, o = t2, o2
	}
	d.hdr = msg[0 : 8*d.n : 8*d.n]
	d.body = msg[8*d.n:]
}

func (d *DecodeState) field(i uint32) (Tag, []byte) {
	tag := Tag(binary.LittleEndian.Uint32(d.hdr[d.n*4+i*4:]))
	start, end := uint32(0), uint32(len(d.body))
	if i > 0 {
		start = binary.LittleEndian.Uint32(d.hdr[i*4:])
	}
	if i+1 < d.n {
		end = binary.LittleEndian.Uint32(d.hdr[(i+1)*4:])
	}
	if end < start || ((end-start)%4 != 0) {
		d.Abort(errInvalidField)
	}
	return tag, d.body[start:end]
}

// Bytes advances through the fields of the message until it finds t and stores
// a slice to the corresponding data in p. The stored slice aliases the message
// buffer.
func (d *DecodeState) Bytes(t Tag, p *[]byte) {
	for ; d.i < d.n; d.i++ {
		tag, value := d.field(d.i)
		if tag > t {
			continue
		}
		if tag < t {
			d.Abort(fmt.Errorf("field %v missing", t))
		}
		*p = value
		d.i++
		return
	}
	d.Abort(errFieldMissing)
}

// Uint32 advances through the fields of the message until it finds t and stores
// the corresponding value as an uint32 in p.
func (d *DecodeState) Uint32(t Tag, p *uint32) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 4 {
		d.Abort(errInvalidField)
	}
	*p = binary.LittleEndian.Uint32(buf)
}

// Uint64 advances through the fields of the message until it finds t and stores
// the corresponding value as an uint64 in p.
func (d *DecodeState) Uint64(t Tag, p *uint64) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 8 {
		d.Abort(errInvalidField)
	}
	*p = binary.LittleEndian.Uint64(buf)
}

// Bytes32 advances through the fields of the message until it finds t and stores
// the corresponding value (which must be 32 bytes long) into p.
func (d *DecodeState) Bytes32(t Tag, p *[32]byte) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 32 {
		d.Abort(errInvalidField)
	}
	copy((*p)[:], buf)
}

// Bytes64 advances through the fields of the message until it finds t and stores
// the corresponding value (which must be 64 bytes long) into p.
func (d *DecodeState) Bytes64(t Tag, p *[64]byte) {
	var buf []byte
	d.Bytes(t, &buf)
	if len(buf) != 64 {
		d.Abort(errInvalidField)
	}
	copy((*p)[:], buf)
}

// Message advances through the fields of the message until it finds t. The
// corresponding value is then decoded using f and also stored in raw. raw
// aliases the message buffer.
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

// Time advances through the fields of the message until it finds t and stores
// the corresponding value (interpreted as an uint64 of microseconds since the
// epoch) into p.
func (d *DecodeState) Time(t Tag, p *time.Time) {
	var v uint64
	d.Uint64(t, &v)
	if v&(1<<63) != 0 {
		d.Abort(errInvalidTimestamp)
	}
	*p = time.Unix(int64(v)/1e6, (int64(v)%1e6)*1e3)
}

// Duration advances through the fields of the message until it finds t and
// stores the corresponding value (interpreted as an uint32 of microseconds)
// into p.
func (d *DecodeState) Duration(t Tag, p *time.Duration) {
	var v uint32
	d.Uint32(t, &v)
	*p = time.Duration(v) * time.Microsecond
	if time.Duration(v) != *p/time.Microsecond {
		d.Abort(errInvalidDuration)
	}
}
