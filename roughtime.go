package roughtime

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	contextCertificate    = []byte("RoughTime v1 delegation signature--\x00")
	contextSignedResponse = []byte("RoughTime v1 response signature\x00")
)

type tagged struct {
	tag Tag
	val []byte
}

func parseHeader(b []byte, t []tagged) (int, error) {
	log.Printf("%x", b)
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	numTags := binary.LittleEndian.Uint32(b)
	if numTags > 128 {
		return 0, errors.New("too many tags")
	}
	if uint32(len(b)/8)+1 < numTags {
		return 0, io.ErrUnexpectedEOF
	}
	if numTags == 0 {
		return 0, nil
	}
	n := numTags * 4
	body := b[2*n:]
	t[0].tag = Tag(binary.LittleEndian.Uint32(b[n:]))
	log.Printf("tag0  = %v", t[0].tag)
	offs := uint32(0)
	for i := uint32(1); i < numTags; i++ {
		o := binary.LittleEndian.Uint32(b[i*4:])
		if o < offs || o >= uint32(len(b)) {
			return 0, errors.New("invalid offset")
		}
		t[i-1].val = body[offs:o]
		t[i].tag = Tag(binary.LittleEndian.Uint32(b[n+i*4:]))
		log.Printf("tag%d  = %v", i, t[i].tag)
		log.Printf("offs%d = %v", i-1, offs)
		offs = o
	}
	t[numTags-1].val = body[offs:]
	log.Printf("offs%d = %v", numTags-1, offs)
	return int(numTags), nil
}

type decoder interface {
	setTag(t Tag, v []byte, root ed25519.PublicKey) error
}

type encoder interface {
	numTags() uint32
	writeTags(func(Tag, int) []byte)
}

func decodeMessage(b []byte, d decoder, root ed25519.PublicKey) error {
	var buf [128]tagged
	var hdr []tagged
	if n, err := parseHeader(b, buf[:]); err != nil {
		return err
	} else {
		hdr = buf[:n]
	}
	for _, t := range hdr {
		log.Printf("%v -> %x", t.tag, t.val)
	}
	for _, t := range hdr {
		if err := d.setTag(t.tag, t.val, root); err != nil {
			return err
		}
	}
	return nil
}

func encodeMessage(b []byte, e encoder) int {
	n := e.numTags()
	if uint32(len(b)) < n*8 || len(b) < 1024 {
		log.Printf("n = %v, len(b) = %v", n, len(b))
		panic("not enough buffer space")
	}
	binary.LittleEndian.PutUint32(b, n)
	hdr, b := b[:n*8], b[n*8:]
	offs := uint32(0)
	i := 0
	var last Tag
	e.writeTags(func(t Tag, l int) []byte {
		log.Printf("writeTags(%v, %d)", t, l)
		if t <= last {
			panic("tags not written in ascending order")
		}
		if len(b) < l {
			panic("not enough buffer space")
		}
		if i >= int(n) {
			panic("too many tags written")
		}
		last = t
		binary.LittleEndian.PutUint32(hdr[4*n+uint32(i)*4:], uint32(t))
		i++
		offs += uint32(l)
		if uint32(i) < n {
			binary.LittleEndian.PutUint32(hdr[uint32(i)*4:], offs)
		}
		r := b[:l]
		b = b[l:]
		return r
	})
	// TODO: Check overflow
	return int(offs) + len(hdr)
}

type Tag uint32

const (
	SIG  Tag = 0x00474953
	NONC     = 0x434e4f4e
	DELE     = 0x454c4544
	PATH     = 0x48544150
	RADI     = 0x49444152
	PUBK     = 0x4b425550
	MIDP     = 0x5044494d
	SREP     = 0x50455253
	MAXT     = 0x5458414d
	ROOT     = 0x544f4f52
	CERT     = 0x54524543
	MINT     = 0x544e494d
	INDX     = 0x58444e49
	PAD      = 0xff444150
)

func init() {
	m := map[Tag]string{
		SIG:  "SIG\\x00",
		NONC: "NONC",
		DELE: "DELE",
		PATH: "PATH",
		RADI: "RADI",
		PUBK: "PUBK",
		MIDP: "MIDP",
		SREP: "SREP",
		MAXT: "MAXT",
		ROOT: "ROOT",
		CERT: "CERT",
		MINT: "MINT",
		INDX: "INDX",
		PAD:  "PAD\\xff",
	}
	for t, s := range m {
		if t.String() != s {
			panic(fmt.Errorf("Tag(%x).String() = %q != %q", t, t.String(), s))
		}
	}
}

func (t Tag) String() string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(t))
	s := strconv.Quote(string(b[:]))
	return s[1 : len(s)-1]
}

var nulls = make([]byte, 1024)

type Request struct {
	Nonce [64]byte
}

func (r *Request) decode(st *decodeState) {
	st.Bytes64(NONC, &r.Nonce)
}

func (r *Request) setTag(t Tag, v []byte, root ed25519.PublicKey) error {
	if t != NONC {
		return nil
	}
	if len(v) != 64 {
		return errors.New("invalid length of nonce")
	}
	log.Printf("Nonce: %x", v)
	copy(r.Nonce[:], v)
	return nil
}

func (r *Request) numTags() uint32 {
	return 2
}

func (r *Request) writeTags(w func(Tag, int) []byte) {
	copy(w(NONC, 64), r.Nonce[:])
	copy(w(PAD, 1024-2*8-64), nulls)
}

type Response struct {
	SignedResponse
	Signature [64]byte
	Index     uint32
	Path      [][64]byte
	Certificate

	srep []byte
}

func (r *Response) decode(st *decodeState) {
	st.Bytes64(SIG, &r.Signature)
	var path []byte
	st.Bytes(PATH, &path)
	if len(path)%64 != 0 {
		st.check(errors.New("invalid PATH"))
	}
	// TODO: Decode path
	st.Message(SREP, r.SignedResponse.decode)
	st.Message(CERT, r.Certificate.decode)
	st.Uint32(INDX, &r.Index)
}

func (r *Response) setTag(t Tag, v []byte, root ed25519.PublicKey) error {
	switch t {
	case SIG:
		if len(v) != 64 {
			return errors.New("invalid SIG")
		}
		log.Printf("Signature: %x", v)
		copy(r.Signature[:], v)
	case PATH:
		if len(v)%64 != 0 {
			return errors.New("invalid path")
		}
		r.Path = make([][64]byte, len(v)/64)
		for i, j := 0, 0; i < len(v); i, j = i+1, j+64 {
			copy(r.Path[i][:], v[j:])
		}
		log.Printf("Path: %x", r.Path)
	case SREP:
		r.srep = v // Need to be kept, until we get CERT
		log.Printf("SREP: %x", v)
		return decodeMessage(v, &r.SignedResponse, root)
	case CERT:
		log.Printf("CERT: %x", v)
		if err := decodeMessage(v, &r.Certificate, root); err != nil {
			return err
		}
		if !ed25519.Verify(r.Certificate.Delegation.PublicKey[:], append(contextSignedResponse, r.srep...), r.Signature[:]) {
			log.Println("signature verification failed")
		}
		r.srep = nil
	case INDX:
		if len(v) != 4 {
			return errors.New("invalid index")
		}
		r.Index = binary.LittleEndian.Uint32(v)
		log.Printf("Index: %v", r.Index)
	}
	return nil
}

type SignedResponse struct {
	Root     [64]byte
	Midpoint time.Time
	Radius   time.Duration
}

func (r *SignedResponse) decode(st *decodeState) {
	st.Bytes64(ROOT, &r.Root)
	st.Time(MIDP, &r.Midpoint)
	st.Duration(RADI, &r.Radius)
}

func (r *SignedResponse) setTag(t Tag, v []byte, root ed25519.PublicKey) error {
	var err error
	switch t {
	case RADI:
		if len(v) != 4 {
			errors.New("invalid radius")
		}
		μs := binary.LittleEndian.Uint32(v)
		r.Radius = time.Duration(μs) * time.Microsecond
	case MIDP:
		r.Midpoint, err = parseTime(v)
	case ROOT:
		if len(v) != 64 {
			return errors.New("invalid ROOT")
		}
		copy(r.Root[:], v)
	}
	return err
}

type Certificate struct {
	Signature [64]byte
	Delegation
}

func (c *Certificate) decode(st *decodeState) {
	st.Bytes64(SIG, &c.Signature)
	st.Message(DELE, c.Delegation.decode)
}

func (c *Certificate) setTag(t Tag, v []byte, root ed25519.PublicKey) error {
	switch t {
	case SIG:
		if len(v) != 64 {
			return errors.New("invalid signature")
		}
		copy(c.Signature[:], v)
	case DELE:
		// SIG is the first message, so we should already have it
		if !ed25519.Verify(root, append(contextCertificate, v...), c.Signature[:]) {
			return errors.New("verification failure")
		}
		if err := decodeMessage(v, &c.Delegation, root); err != nil {
			return err
		}
	}
	return nil
}

type Delegation struct {
	Min       time.Time
	Max       time.Time
	PublicKey [32]byte
}

func (d *Delegation) decode(st *decodeState) {
	st.Time(MINT, &d.Min)
	st.Time(MAXT, &d.Max)
	st.Bytes32(PUBK, &d.PublicKey)
}

func (d *Delegation) setTag(t Tag, v []byte, root ed25519.PublicKey) error {
	var err error
	switch t {
	case PUBK:
		if len(v) != 32 {
			return errors.New("invalid PUBK")
		}
		copy(d.PublicKey[:], v)
	case MINT:
		d.Min, err = parseTime(v)
	case MAXT:
		d.Max, err = parseTime(v)
	}
	return err
}

func parseTime(v []byte) (time.Time, error) {
	if len(v) != 8 || (v[7]&0x80 != 0) {
		return time.Time{}, errors.New("invalid timestamp")
	}
	μs := binary.LittleEndian.Uint64(v)
	return time.Unix(int64(μs)/1e6, (int64(μs)%1e6)*1e3), nil
}

func ParseResponse(resp, nonce []byte, root ed25519.PublicKey) (m time.Time, r time.Duration, err error) {
	var res Response
	if err := decodeMessage(resp, &res, root); err != nil {
		return time.Time{}, 0, err
	}
	if len(nonce) != 64 {
		panic("nonce has wrong length")
	}

	idx := res.Index
	path := res.Path
	hash := hashLeaf(nonce)
	for len(path) > 0 {
		if idx&1 == 0 {
			hash = hashNode(hash, path[0])
		} else {
			hash = hashNode(path[0], hash)
		}
		idx >>= 1
		path = path[1:]
	}
	if hash != res.Root {
		return time.Time{}, 0, errors.New("verification error")
	}

	mp := res.Midpoint
	if mp.Before(res.Min) || mp.After(res.Max) {
		return time.Time{}, 0, errors.New("invalid midpoint")
	}
	return res.Midpoint, res.Radius, nil
}

func hashLeaf(b []byte) [64]byte {
	var r [64]byte
	h := sha512.New()
	h.Write([]byte{0})
	h.Write(b)
	h.Sum(r[:])
	return r
}

func hashNode(l, r [64]byte) [64]byte {
	var res [64]byte
	h := sha512.New()
	h.Write([]byte{0})
	h.Write(l[:])
	h.Write(r[:])
	h.Sum(res[:])
	return res
}

func FetchRoughtime(addr string, key ed25519.PublicKey) (m time.Time, r time.Duration, err error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return m, r, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return m, r, err
	}
	defer conn.Close()

	var req Request
	_, err = io.ReadFull(rand.Reader, req.Nonce[:])
	if err != nil {
		return m, r, err
	}
	for i := 0; i < 64; i++ {
		req.Nonce[i] = byte(i)
	}
	msg := make([]byte, 1024)
	msg = msg[:encodeMessage(msg, &req)]
	if len(msg) != 1024 {
		panic("message too short")
	}
	_, err = conn.WriteTo(msg, a)
	if err != nil {
		return m, r, err
	}
	msg = msg[:1024]
	n, _, err := conn.ReadFromUDP(msg)
	if err != nil {
		return m, r, err
	}
	msg = msg[:n]
	var resp Response
	if err = decodeMessage(msg, &resp, key); err != nil {
		return m, r, err
	}
	return resp.Midpoint, resp.Radius, nil
}
