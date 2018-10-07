package roughtime

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Merovius/roughtime/internal/wire"

	"golang.org/x/crypto/ed25519"
)

var (
	contextCertificate    = []byte("RoughTime v1 delegation signature--\x00")
	contextSignedResponse = []byte("RoughTime v1 response signature\x00")
)

const (
	tSIG  wire.Tag = 0x00474953
	tNONC          = 0x434e4f4e
	tDELE          = 0x454c4544
	tPATH          = 0x48544150
	tRADI          = 0x49444152
	tPUBK          = 0x4b425550
	tMIDP          = 0x5044494d
	tSREP          = 0x50455253
	tMAXT          = 0x5458414d
	tROOT          = 0x544f4f52
	tCERT          = 0x54524543
	tMINT          = 0x544e494d
	tINDX          = 0x58444e49
	tPAD           = 0xff444150
)

type request struct {
	nonce [64]byte
}

func (r *request) decode(st *wire.DecodeState) {
	st.Bytes64(tNONC, &r.nonce)
}

func (r *request) encode(st *wire.EncodeState) {
	st.NTags(2)
	st.Bytes64(tNONC, r.nonce)
	// 16 Byte header + 64 byte nonce + 944 byte padding = 1024 byte total
	st.Bytes(tPAD, 944)
}

type response struct {
	signedResponse
	signature [64]byte
	index     uint32
	path      [][64]byte
	certificate
}

func (r *response) decodePath(st *wire.DecodeState) {
	var path []byte
	st.Bytes(tPATH, &path)
	if len(path)%64 != 0 {
		st.Abort(errors.New("invalid PATH"))
	}
	r.path = make([][64]byte, len(path)/64)
	for i, j := 0, 0; i < len(path); i, j = i+64, j+1 {
		copy(r.path[j][:], path[i:])
	}
}

func (r *response) decode(st *wire.DecodeState) {
	st.Bytes64(tSIG, &r.signature)
	r.decodePath(st)
	st.Message(tSREP, &r.signedResponse.raw, r.signedResponse.decode)
	st.Message(tCERT, &r.certificate.raw, r.certificate.decode)
	st.Uint32(tINDX, &r.index)
}

func (r *response) encode(st *wire.EncodeState) {
	st.NTags(4)
	st.Bytes64(tSIG, r.signature)
	st.Message(tSREP, r.signedResponse.encode)
	st.Message(tCERT, r.certificate.encode)
	st.Uint32(tINDX, r.index)
}

type signedResponse struct {
	raw []byte

	root     [64]byte
	midpoint time.Time
	radius   time.Duration
}

func (r *signedResponse) decode(st *wire.DecodeState) {
	st.Duration(tRADI, &r.radius)
	st.Time(tMIDP, &r.midpoint)
	st.Bytes64(tROOT, &r.root)
}

func (r *signedResponse) encode(st *wire.EncodeState) {
	st.NTags(3)
	st.Bytes64(tROOT, r.root)
	st.Time(tMIDP, r.midpoint)
	st.Duration(tRADI, r.radius)
}

type certificate struct {
	signature [64]byte
	delegation
}

func (c *certificate) decode(st *wire.DecodeState) {
	st.Bytes64(tSIG, &c.signature)
	st.Message(tDELE, &c.delegation.raw, c.delegation.decode)
}

func (c *certificate) encode(st *wire.EncodeState) {
	st.NTags(2)
	st.Bytes64(tSIG, c.signature)
	st.Message(tDELE, c.delegation.encode)
}

type delegation struct {
	raw []byte

	min       time.Time
	max       time.Time
	publicKey [32]byte
}

func (d *delegation) decode(st *wire.DecodeState) {
	st.Bytes32(tPUBK, &d.publicKey)
	st.Time(tMINT, &d.min)
	st.Time(tMAXT, &d.max)
}

func (d *delegation) encode(st *wire.EncodeState) {
	st.NTags(3)
	st.Time(tMINT, d.min)
	st.Time(tMAXT, d.max)
	st.Bytes32(tPUBK, d.publicKey)
}

func ParseResponse(resp, nonce []byte, root ed25519.PublicKey) (m time.Time, r time.Duration, err error) {
	var res response
	if err := wire.Decode(resp, res.decode); err != nil {
		return time.Time{}, 0, err
	}
	if len(nonce) != 64 {
		panic("nonce has wrong length")
	}
	if !ed25519.Verify(root, append(contextCertificate, res.certificate.delegation.raw...), res.certificate.signature[:]) {
		return time.Time{}, 0, errors.New("bad delegation")
	}
	if !ed25519.Verify(res.certificate.delegation.publicKey[:], append(contextSignedResponse, res.signedResponse.raw...), res.signature[:]) {
		return time.Time{}, 0, errors.New("bad signature")
	}

	idx := res.index
	path := res.path
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
	if hash != res.root {
		return time.Time{}, 0, errors.New("verification error")
	}

	mp := res.midpoint
	if mp.Before(res.min) || mp.After(res.max) {
		return time.Time{}, 0, errors.New("invalid midpoint")
	}
	return res.midpoint, res.radius, nil
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

	var req request
	_, err = io.ReadFull(rand.Reader, req.nonce[:])
	if err != nil {
		return m, r, err
	}
	for i := 0; i < 64; i++ {
		req.nonce[i] = byte(i)
	}
	msg := wire.Encode(req.encode)
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
	var resp response
	if err = wire.Decode(msg, resp.decode); err != nil {
		return m, r, err
	}
	// TODO: Validate response
	return resp.midpoint, resp.radius, nil
}
