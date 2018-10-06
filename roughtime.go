package roughtime

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	contextCertificate    = []byte("RoughTime v1 delegation signature--\x00")
	contextSignedResponse = []byte("RoughTime v1 response signature\x00")
)

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

type Request struct {
	Nonce [64]byte
}

func (r *Request) decode(st *decodeState) {
	st.Bytes64(NONC, &r.Nonce)
}

func (r *Request) encode(st *encodeState) {
	st.NTags(2)
	st.Bytes64(NONC, r.Nonce)
	// 16 Byte header + 64 byte nonce + 944 byte padding = 1024 byte total
	st.Bytes(PAD, 944)
}

type Response struct {
	SignedResponse
	Signature [64]byte
	Index     uint32
	Path      [][64]byte
	Certificate
}

func (r *Response) decodePath(st *decodeState) {
	var path []byte
	st.Bytes(PATH, &path)
	if len(path)%64 != 0 {
		st.check(errors.New("invalid PATH"))
	}
	r.Path = make([][64]byte, len(path)/64)
	for i, j := 0, 0; i < len(path); i, j = i+64, j+1 {
		copy(r.Path[j][:], path[i:])
	}
}

func (r *Response) decode(st *decodeState) {
	st.Bytes64(SIG, &r.Signature)
	r.decodePath(st)
	st.Message(SREP, r.SignedResponse.decode)
	st.Message(CERT, r.Certificate.decode)
	st.Uint32(INDX, &r.Index)
}

func (r *Response) encode(st *encodeState) {
	st.NTags(4)
	st.Bytes64(SIG, r.Signature)
	st.Message(SREP, r.SignedResponse.encode)
	st.Message(CERT, r.Certificate.encode)
	st.Uint32(INDX, r.Index)
}

type SignedResponse struct {
	Root     [64]byte
	Midpoint time.Time
	Radius   time.Duration
}

func (r *SignedResponse) decode(st *decodeState) {
	st.Duration(RADI, &r.Radius)
	st.Time(MIDP, &r.Midpoint)
	st.Bytes64(ROOT, &r.Root)
}

func (r *SignedResponse) encode(st *encodeState) {
	st.NTags(3)
	st.Bytes64(ROOT, r.Root)
	st.Time(MIDP, r.Midpoint)
	st.Duration(RADI, r.Radius)
}

type Certificate struct {
	Signature [64]byte
	Delegation
}

func (c *Certificate) decode(st *decodeState) {
	st.Bytes64(SIG, &c.Signature)
	st.Message(DELE, c.Delegation.decode)
}

func (c *Certificate) encode(st *encodeState) {
	st.NTags(2)
	st.Bytes64(SIG, c.Signature)
	st.Message(DELE, c.Delegation.encode)
}

type Delegation struct {
	Min       time.Time
	Max       time.Time
	PublicKey [32]byte
}

func (d *Delegation) decode(st *decodeState) {
	st.Bytes32(PUBK, &d.PublicKey)
	st.Time(MINT, &d.Min)
	st.Time(MAXT, &d.Max)
}

func (d *Delegation) encode(st *encodeState) {
	st.NTags(3)
	st.Time(MINT, d.Min)
	st.Time(MAXT, d.Max)
	st.Bytes32(PUBK, d.PublicKey)
}

func ParseResponse(resp, nonce []byte, root ed25519.PublicKey) (m time.Time, r time.Duration, err error) {
	var res Response
	if err := decode(resp, res.decode); err != nil {
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
	msg := encode(req.encode)
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
	if err = decode(msg, resp.decode); err != nil {
		return m, r, err
	}
	// TODO: Validate response
	return resp.Midpoint, resp.Radius, nil
}
