// Package wire defines the language-independent Auth Go v2 cryptographic framing.
// It uses only the standard library. See server/internal/apidocs/protocol.md and sdk/vectors.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

var B64 = base64.RawURLEncoding
var ErrInvalid = errors.New("无效的加密消息")

type Request struct {
	V int    `json:"v"`
	K string `json:"k"`
	E string `json:"e"`
	N string `json:"n"`
	C string `json:"c"`
}
type Response struct {
	N string `json:"n"`
	C string `json:"c"`
}
type Inner struct {
	AppKey    string          `json:"app_key"`
	Op        string          `json:"op"`
	Timestamp string          `json:"timestamp"`
	Nonce     string          `json:"nonce"`
	Signature string          `json:"signature"`
	Body      json.RawMessage `json:"body"`
}
type Session struct{ RequestKey, ResponseKey, AAD, ResponseAAD []byte }

func Hash(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
func HKDF(ikm, salt, info []byte, n int) []byte {
	if n < 1 || n > 255*32 {
		panic("HKDF length")
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)
	out := []byte{}
	var prev []byte
	for i := byte(1); len(out) < n; i++ {
		h = hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}
func MAC(secret []byte, op, ts, nonce string, body []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(op + ts + nonce + Hash(body)))
	return hex.EncodeToString(h.Sum(nil))
}
func KeyID(public []byte) string     { return Hash(public)[:16] }
func Pad(raw []byte) ([]byte, error) { return PadWith(raw, rand.Reader) }
func PadWith(raw []byte, random io.Reader) ([]byte, error) {
	n := max(4096, ((len(raw)+4+511)/512)*512)
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(raw)))
	copy(out[4:], raw)
	_, e := io.ReadFull(random, out[4+len(raw):])
	return out, e
}
func Unpad(p []byte) ([]byte, error) {
	if len(p) == 0 || len(p)%512 != 0 {
		return nil, ErrInvalid
	}
	n := int(binary.BigEndian.Uint32(p))
	if n < 1 || n > len(p)-4 || len(p) != max(4096, ((n+4+511)/512)*512) {
		return nil, ErrInvalid
	}
	return p[4 : 4+n], nil
}
func derive(private *ecdh.PrivateKey, public []byte, k, e string) (*Session, error) {
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, ErrInvalid
	}
	shared, err := private.ECDH(pub)
	if err != nil {
		return nil, ErrInvalid
	}
	aad := []byte("authgo-gateway-v2\x00" + k + "\x00" + e)
	salt := sha256.Sum256(aad)
	return &Session{RequestKey: HKDF(shared, salt[:], []byte("authgo/v2/request"), 32), ResponseKey: HKDF(shared, salt[:], []byte("authgo/v2/response"), 32), AAD: aad}, nil
}
func Seal(key, nonce, plain, aad []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return nil, ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return g.Seal(nil, nonce, plain, aad), nil
}
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return nil, ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return g.Open(nil, nonce, ciphertext, aad)
}
func decode(s string, n int) ([]byte, error) {
	b, e := B64.Strict().DecodeString(s)
	if e != nil || B64.EncodeToString(b) != s || n > 0 && len(b) != n {
		return nil, ErrInvalid
	}
	return b, nil
}
func (s *Session) bind(r Request) {
	s.ResponseAAD = append(append([]byte(nil), s.AAD...), []byte("\x00"+Hash([]byte(r.N+"."+r.C)))...)
}
func Encrypt(public []byte, raw []byte) (Request, *Session, error) {
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return Request{}, nil, e
	}
	return EncryptWith(priv, public, raw, rand.Reader)
}
func EncryptWith(priv *ecdh.PrivateKey, public, raw []byte, random io.Reader) (Request, *Session, error) {
	r := Request{V: 2, K: KeyID(public), E: B64.EncodeToString(priv.PublicKey().Bytes())}
	s, e := derive(priv, public, r.K, r.E)
	if e != nil {
		return r, nil, e
	}
	p, e := PadWith(raw, random)
	if e != nil {
		return r, nil, e
	}
	n := make([]byte, 12)
	if _, e = io.ReadFull(random, n); e != nil {
		return r, nil, e
	}
	c, e := Seal(s.RequestKey, n, p, s.AAD)
	r.N = B64.EncodeToString(n)
	r.C = B64.EncodeToString(c)
	s.bind(r)
	return r, s, e
}
func Decrypt(priv *ecdh.PrivateKey, r Request) ([]byte, *Session, error) {
	if r.V != 2 || r.K != KeyID(priv.PublicKey().Bytes()) {
		return nil, nil, ErrInvalid
	}
	pub, e := decode(r.E, 32)
	if e != nil {
		return nil, nil, e
	}
	s, e := derive(priv, pub, r.K, r.E)
	if e != nil {
		return nil, nil, e
	}
	n, e := decode(r.N, 12)
	if e != nil {
		return nil, nil, e
	}
	c, e := decode(r.C, 0)
	if e != nil {
		return nil, nil, e
	}
	p, e := Open(s.RequestKey, n, c, s.AAD)
	if e != nil {
		return nil, nil, ErrInvalid
	}
	raw, e := Unpad(p)
	s.bind(r)
	return raw, s, e
}
func (s *Session) EncryptResponse(raw []byte) (Response, error) {
	p, e := Pad(raw)
	if e != nil {
		return Response{}, e
	}
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		return Response{}, e
	}
	c, e := Seal(s.ResponseKey, n, p, s.ResponseAAD)
	return Response{B64.EncodeToString(n), B64.EncodeToString(c)}, e
}
func (s *Session) DecryptResponse(r Response) ([]byte, error) {
	n, e := decode(r.N, 12)
	if e != nil {
		return nil, e
	}
	c, e := decode(r.C, 0)
	if e != nil {
		return nil, e
	}
	p, e := Open(s.ResponseKey, n, c, s.ResponseAAD)
	if e != nil {
		return nil, ErrInvalid
	}
	return Unpad(p)
}
