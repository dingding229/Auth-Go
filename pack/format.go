// Package pack implements the language-neutral AuthGo encrypted payload format.
package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
)

const ChunkSize = 1 << 20
const MaxManifest = 8 << 20

var invalid = errors.New("invalid encrypted payload")

type canonicalBase64 struct{}

var b64 canonicalBase64

func (canonicalBase64) EncodeToString(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
func (canonicalBase64) DecodeString(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, invalid
	}
	return b, nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9_-]+$`)
var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// File describes one ciphertext stream. Size is the plaintext stream size,
// including tar framing for directories. Indexes are implicit array positions.
type File struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	ChunkSize     int    `json:"chunk_size"`
	Encoding      string `json:"encoding"`
	PythonVersion string `json:"python_version,omitempty"`
	MainClass     string `json:"main_class,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
}
type Manifest struct {
	Files []File `json:"files"`
}
type Envelope struct {
	E string `json:"e"`
	N string `json:"n"`
	C string `json:"c"`
}
type Payload struct {
	V        int      `json:"v"`
	AppKey   string   `json:"app_key"`
	Version  string   `json:"version"`
	BuiltAt  string   `json:"built_at"`
	KeyID    string   `json:"key_id"`
	Config   string   `json:"config"`
	Manifest string   `json:"manifest"`
	Envelope Envelope `json:"envelope"`
}

func validVersion(s string) bool {
	if len(s) > 256 || !semverRE.MatchString(s) {
		return false
	}
	core := strings.SplitN(s, "+", 2)[0]
	if p := strings.SplitN(core, "-", 2); len(p) == 2 {
		for _, id := range strings.Split(p[1], ".") {
			if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}
func lp(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}
func (p Payload) aad() ([]byte, error) {
	if p.V != 2 || len(p.AppKey) == 0 || len(p.AppKey) > 256 || !nameRE.MatchString(p.KeyID) || len(p.KeyID) > 128 || !validVersion(p.Version) {
		return nil, invalid
	}
	t, e := time.Parse(time.RFC3339, p.BuiltAt)
	if e != nil || t.UTC().Format("2006-01-02T15:04:05Z") != p.BuiltAt {
		return nil, invalid
	}
	if err := validateConfig(p.Config, p.AppKey); err != nil {
		return nil, invalid
	}
	raw, e := b64.DecodeString(p.Manifest)
	if e != nil || len(raw) > MaxManifest {
		return nil, invalid
	}
	if _, e = decodeManifestVersion(raw, p.V); e != nil {
		return nil, e
	}
	a := []byte(fmt.Sprintf("authgo-payload-envelope-v%d\x00", p.V))
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID, p.Config} {
		a = lp(a, s)
	}
	h := sha256.Sum256(raw)
	return append(a, h[:]...), nil
}
func decodeManifest(raw []byte) (Manifest, error) { return decodeManifestVersion(raw, 2) }
func decodeManifestVersion(raw []byte, version int) (Manifest, error) {
	var m Manifest
	if version != 2 {
		return m, invalid
	}
	if err := strictJSON(raw, &m); err != nil || len(m.Files) == 0 || len(m.Files) > 65535 {
		return m, invalid
	}
	var shape struct {
		Files []map[string]json.RawMessage `json:"files"`
	}
	if json.Unmarshal(raw, &shape) != nil {
		return m, invalid
	}
	names := map[string]bool{}
	metadata := 0
	for i, f := range m.Files {
		if !nameRE.MatchString(f.Name) || len(f.Name) > 128 || names[f.Name] || f.Path != cipherName(i) || f.Size < 0 || f.Size > math.MaxInt64/2 || f.ChunkSize != ChunkSize {
			return m, invalid
		}
		names[f.Name] = true
		switch f.Kind {
		case "watermark":
			if len(shape.Files[i]) != 6 || version != 2 || f.Name != watermarkIndexName || f.Encoding != "raw" || f.Size < 1 || f.Size > watermarkIndexMax || f.PythonVersion != "" || f.MainClass != "" || f.Architecture != "" {
				return m, invalid
			}
			metadata++
		case "python", "php", "dotnet":
			if f.Encoding != "tar" {
				return m, invalid
			}
		case "node", "java", "protect":
			if f.Encoding != "raw" {
				return m, invalid
			}
		default:
			return m, invalid
		}
		if f.Kind == "python" && f.PythonVersion == "" {
			return m, invalid
		}
		if f.Kind == "protect" && f.Architecture != "amd64" && f.Architecture != "arm64" {
			return m, invalid
		}
	}
	if metadata != 1 || len(m.Files) < 2 {
		return m, invalid
	}
	return m, nil
}
func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, invalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, invalid
	}
	return cipher.NewGCM(b)
}
func wrap(p *Payload, key, public []byte, random io.Reader) error {
	a, e := p.aad()
	if e != nil {
		return e
	}
	pub, e := ecdh.X25519().NewPublicKey(public)
	if e != nil {
		return invalid
	}
	// Explicit raw scalar bytes also make the public synthetic vectors
	// reproducible on Go 1.26 (GenerateKey now ignores custom readers).
	scalar := make([]byte, 32)
	if _, e = io.ReadFull(random, scalar); e != nil {
		return errors.New("random source failed")
	}
	priv, e := ecdh.X25519().NewPrivateKey(scalar)
	clear(scalar)
	if e != nil {
		return invalid
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		return invalid
	}
	a = append(a, priv.PublicKey().Bytes()...)
	salt := sha256.Sum256(a)
	kek, e := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/wrap", 32)
	if e != nil {
		return invalid
	}
	g, _ := aead(kek)
	n := make([]byte, 12)
	if _, e = io.ReadFull(random, n); e != nil {
		return errors.New("random source failed")
	}
	p.Envelope = Envelope{b64.EncodeToString(priv.PublicKey().Bytes()), b64.EncodeToString(n), b64.EncodeToString(g.Seal(nil, n, key, a))}
	return nil
}

// Unlock authenticates all metadata before returning the content key.
func Unlock(p Payload, private []byte) ([]byte, error) {
	a, e := p.aad()
	if e != nil {
		return nil, invalid
	}
	priv, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, invalid
	}
	ep, e := b64.DecodeString(p.Envelope.E)
	if e != nil {
		return nil, invalid
	}
	pub, e := ecdh.X25519().NewPublicKey(ep)
	if e != nil {
		return nil, invalid
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		return nil, invalid
	}
	a = append(a, ep...)
	salt := sha256.Sum256(a)
	kek, e := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/wrap", 32)
	if e != nil {
		return nil, invalid
	}
	n, e := b64.DecodeString(p.Envelope.N)
	if e != nil || len(n) != 12 {
		return nil, invalid
	}
	c, e := b64.DecodeString(p.Envelope.C)
	if e != nil || len(c) != 48 {
		return nil, invalid
	}
	g, _ := aead(kek)
	key, e := g.Open(nil, n, c, a)
	if e != nil {
		return nil, invalid
	}
	return key, nil
}
func binding(p Payload) ([]byte, error) {
	a, e := p.aad()
	if e != nil {
		return nil, e
	}
	for _, v := range []struct {
		s string
		n int
	}{{p.Envelope.E, 32}, {p.Envelope.N, 12}, {p.Envelope.C, 48}} {
		b, e := b64.DecodeString(v.s)
		if e != nil || len(b) != v.n {
			return nil, invalid
		}
		a = append(a, b...)
	}
	h := sha256.Sum256(a)
	return h[:], nil
}
func nonce(file uint32, chunk uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n, file)
	binary.BigEndian.PutUint64(n[4:], chunk)
	return n
}
func chunkAAD(bind []byte, file uint32, chunk uint64, last bool) []byte {
	a := append([]byte("authgo-payload-chunk-v1\x00"), bind...)
	a = append(a, nonce(file, chunk)...)
	if last {
		return append(a, 1)
	}
	return append(a, 0)
}
func chunkCount(size int64) int64 {
	if size == 0 {
		return 1
	}
	return (size-1)/ChunkSize + 1
}
func CipherSize(size int64) int64 { return size + 16*chunkCount(size) }
func encrypt(w io.Writer, r io.Reader, size int64, key, bind []byte, file uint32) error {
	g, e := aead(key)
	if e != nil {
		return e
	}
	buf := make([]byte, ChunkSize+g.Overhead())
	for i := int64(0); i < chunkCount(size); i++ {
		n := min(int64(ChunkSize), size-i*ChunkSize)
		if _, e = io.ReadFull(r, buf[:n]); e != nil {
			return errors.New("input changed or unreadable")
		}
		c := g.Seal(buf[:0], nonce(file, uint64(i)), buf[:n], chunkAAD(bind, file, uint64(i), i == chunkCount(size)-1))
		if written, err := w.Write(c); err != nil || written != len(c) {
			return errors.New("ciphertext write failed")
		}
	}
	var extra [1]byte
	n, e := r.Read(extra[:])
	if n != 0 || e != io.EOF {
		return errors.New("input changed or unreadable")
	}
	return nil
}

// ReadChunk uses exactly one ReadAt; no preceding block is read. The caller
// must obtain key via Unlock (or the authenticated server response).
func ReadChunk(r io.ReaderAt, total int64, p Payload, key []byte, file uint32, chunk uint64) ([]byte, error) {
	_, e := p.aad()
	if e != nil {
		return nil, invalid
	}
	raw, _ := b64.DecodeString(p.Manifest)
	m, _ := decodeManifestVersion(raw, p.V)
	if uint64(file) >= uint64(len(m.Files)) {
		return nil, invalid
	}
	f := m.Files[file]
	if total != CipherSize(f.Size) || chunk >= uint64(chunkCount(f.Size)) {
		return nil, invalid
	}
	bind, e := binding(p)
	if e != nil {
		return nil, invalid
	}
	g, e := aead(key)
	if e != nil {
		return nil, e
	}
	n := min(int64(ChunkSize), f.Size-int64(chunk)*ChunkSize)
	buf := make([]byte, n+16)
	if _, e = r.ReadAt(buf, int64(chunk)*(ChunkSize+16)); e != nil {
		return nil, invalid
	}
	plain, e := g.Open(buf[:0], nonce(file, chunk), buf, chunkAAD(bind, file, chunk, chunk == uint64(chunkCount(f.Size)-1)))
	if e != nil {
		return nil, invalid
	}
	return plain, nil
}

// NewPayload generates a fresh key and envelope for every invocation.
func NewPayload(p Payload, m Manifest, public []byte) (Payload, []byte, error) {
	raw, e := json.Marshal(m)
	if e != nil {
		return p, nil, invalid
	}
	if p.V == 0 {
		p.V = 2
	}
	p.Manifest = b64.EncodeToString(raw)
	key := make([]byte, 32)
	if _, e = io.ReadFull(rand.Reader, key); e != nil {
		return p, nil, errors.New("random source failed")
	}
	if e = wrap(&p, key, public, rand.Reader); e != nil {
		clear(key)
		return p, nil, e
	}
	return p, key, nil
}

// ParsePayload is the strict decoder for wire metadata. It checks structure,
// not authenticity; call Unlock before trusting metadata for license decisions.
func ParsePayload(raw []byte) (Payload, error) {
	var p Payload
	if len(raw) > 12<<20 || strictJSON(raw, &p) != nil {
		return p, invalid
	}
	if _, e := binding(p); e != nil {
		return p, invalid
	}
	return p, nil
}
