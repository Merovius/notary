package roughtime

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"net"
	"time"

	config "github.com/Merovius/roughtime/internal/config"
	"github.com/Merovius/roughtime/internal/wire"
	"github.com/golang/protobuf/jsonpb"

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
	raw []byte

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

func hashLeaf(b []byte) [64]byte {
	var res [64]byte
	h := sha512.New()
	h.Write([]byte{0})
	h.Write(b)
	h.Sum(res[:0])
	return res
}

func hashNode(l, r [64]byte) [64]byte {
	var res [64]byte
	h := sha512.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	h.Sum(res[:0])
	return res
}

func ensureNonce(nonce []byte) ([]byte, error) {
	if nonce != nil {
		if len(nonce) != 64 {
			panic("nonce needs to have 64 bytes")
		}
		return nonce, nil
	}
	nonce = make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonce)
	return nonce, err
}

type Server struct {
	Address   string
	PublicKey ed25519.PublicKey
}

func fetchRoughtime(s *Server, nonce []byte) ([]byte, error) {
	a, err := net.ResolveUDPAddr("udp", s.Address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(nonce) != 64 {
		panic("nonce has wrong length")
	}

	var req request
	copy(req.nonce[:], nonce)
	msg := wire.Encode(req.encode)
	if len(msg) != 1024 {
		panic("message too short")
	}
	_, err = conn.WriteTo(msg, a)
	if err != nil {
		return nil, err
	}
	msg = msg[:1024]
	n, _, err := conn.ReadFromUDP(msg)
	if err != nil {
		return nil, err
	}
	return msg[:n], nil
}

func FetchRoughtime(s *Server, nonce []byte) (m time.Time, r time.Duration, err error) {
	nonce, err = ensureNonce(nonce)
	if err != nil {
		return m, r, err
	}
	msg, err := fetchRoughtime(s, nonce)
	if err != nil {
		return m, r, err
	}
	return ParseResponse(msg, nonce, s.PublicKey)
}

func ParseResponse(resp, nonce []byte, root ed25519.PublicKey) (m time.Time, r time.Duration, err error) {
	var res response
	if err := wire.Decode(resp, res.decode); err != nil {
		return time.Time{}, 0, err
	}
	if len(nonce) != 64 {
		panic("nonce needs to have 64 bytes")
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
		return time.Time{}, 0, errors.New("nonce does not match")
	}

	mp := res.midpoint
	if mp.Before(res.min) || mp.After(res.max) {
		return time.Time{}, 0, errors.New("invalid midpoint")
	}
	return res.midpoint, res.radius, nil
}

func Chain(w io.Writer, s *config.ServersJSON, nonce []byte) error {
	nonce, err := ensureNonce(nonce)
	if err != nil {
		return err
	}

	c := new(config.Chain)
	c.Links = make([]*config.Link, len(s.Servers))
	for i, s := range s.Servers {
		l := &config.Link{
			PublicKeyType:   s.PublicKeyType,
			ServerPublicKey: s.PublicKey,
		}
		l.NonceOrBlind = nonce
		if i > 0 {
			l.NonceOrBlind = make([]byte, 64)
			_, err = io.ReadFull(rand.Reader, l.NonceOrBlind)
			if err != nil {
				return err
			}
			nonce = hash512(hash512(c.Links[i-1].Reply), l.NonceOrBlind)
		}
		resp, err := fetchRoughtime(&Server{Address: s.Addresses[0].Address, PublicKey: s.PublicKey}, nonce)
		if err != nil {
			return err
		}
		l.Reply = resp
		c.Links[i] = l
		if _, _, err = ParseResponse(resp, nonce, s.PublicKey); err != nil {
			return err
		}
	}
	return new(jsonpb.Marshaler).Marshal(w, c)
}

func ReadServersJSON(r io.Reader) (*config.ServersJSON, error) {
	servers := new(config.ServersJSON)
	return servers, jsonpb.Unmarshal(r, servers)
}

func VerifyChain(r io.Reader, s *config.ServersJSON) error {
	byKey := make(map[string]string)
	for _, s := range s.Servers {
		byKey[string(s.PublicKey)] = s.Name
	}
	c := new(config.Chain)
	if err := jsonpb.Unmarshal(r, c); err != nil {
		return err
	}
	var prevHash []byte
	for i, l := range c.Links {
		nonce := l.NonceOrBlind
		if i > 0 {
			nonce = hash512(prevHash, l.NonceOrBlind)
		}
		_, _, err := ParseResponse(l.Reply, nonce, l.ServerPublicKey)
		if err != nil {
			return err
		}
		prevHash = hash512(l.Reply)
	}
	return nil
}

func hash512(b ...[]byte) []byte {
	h := sha512.New()
	for _, b := range b {
		h.Write(b)
	}
	return h.Sum(nil)
}
