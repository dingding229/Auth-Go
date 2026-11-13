package payloadkey

import (
	cryptoutil "authgo/internal/crypto"
	"bytes"
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
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// The whole payload must fit the existing 64 KiB decrypted gateway body.
const MaxPayload = 65536
const maxConfig = 32768

var ErrInvalid = errors.New("invalid encrypted payload")
var namePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

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
type manifestFile struct {
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

func b64(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrInvalid
	}
	return b, nil
}

// Exact field names, no duplicate keys, case aliases, null required values or
// missing fields. The shared canonical parser also validates Unicode escapes.
func strict(raw []byte, out any) error {
	if _, e := cryptoutil.CanonicalizeJSON(raw); e != nil {
		return ErrInvalid
	}
	var shape func(json.RawMessage, reflect.Type, int) error
	shape = func(raw json.RawMessage, t reflect.Type, depth int) error {
		if depth > 64 {
			return ErrInvalid
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && t.Kind() != reflect.Slice {
			return ErrInvalid
		}
		switch t.Kind() {
		case reflect.Struct:
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				return ErrInvalid
			}
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")
				v, ok := fields[tag[0]]
				if !ok {
					if len(tag) > 1 && tag[1] == "omitempty" {
						continue
					}
					return ErrInvalid
				}
				if e := shape(v, f.Type, depth+1); e != nil {
					return e
				}
				delete(fields, tag[0])
			}
			if len(fields) != 0 {
				return ErrInvalid
			}
		case reflect.Slice:
			var items []json.RawMessage
			if json.Unmarshal(raw, &items) != nil {
				return ErrInvalid
			}
			for _, item := range items {
				if e := shape(item, t.Elem(), depth+1); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := shape(raw, reflect.TypeOf(out).Elem(), 0); e != nil {
		return e
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrInvalid
	}
	return nil
}
func Parse(raw []byte) (Payload, error) {
	var p Payload
	if len(raw) > MaxPayload || strict(raw, &p) != nil {
		return p, ErrInvalid
	}
	if _, e := p.aad(); e != nil {
		return p, ErrInvalid
	}
	return p, nil
}
func lp(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}
func validConfig(s, app string) bool {
	if len(s) > maxConfig || !strings.HasPrefix(s, "authgo2.") {
		return false
	}
	raw, e := b64(strings.TrimPrefix(s, "authgo2."))
	if e != nil {
		return false
	}
	var c struct {
		URL        string `json:"url"`
		AppKey     string `json:"app_key"`
		AppSecret  string `json:"app_secret"`
		PublicKey  string `json:"public_key"`
		GatewayKey string `json:"gateway_key"`
	}
	if strict(raw, &c) != nil || c.AppKey != app || c.AppSecret == "" {
		return false
	}
	https := func(s string) bool {
		u, e := url.Parse(s)
		return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
	}
	if !https(c.URL) {
		return false
	}
	pub, e := base64.StdEncoding.Strict().DecodeString(c.PublicKey)
	if e != nil || len(pub) != 32 {
		return false
	}
	g, e := b64(c.GatewayKey)
	return e == nil && len(g) == 32
}
func (p Payload) aad() ([]byte, error) {
	if p.V != 2 || p.AppKey == "" || len(p.AppKey) > 256 || len(p.KeyID) > 128 || !namePattern.MatchString(p.KeyID) || len(p.Version) > 256 {
		return nil, ErrInvalid
	}
	if !versionPattern.MatchString(p.Version) {
		return nil, ErrInvalid
	}
	core := strings.SplitN(p.Version, "+", 2)[0]
	if parts := strings.SplitN(core, "-", 2); len(parts) == 2 {
		for _, id := range strings.Split(parts[1], ".") {
			if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
				return nil, ErrInvalid
			}
		}
	}
	t, e := time.Parse(time.RFC3339, p.BuiltAt)
	if e != nil || t.UTC().Format("2006-01-02T15:04:05Z") != p.BuiltAt || !validConfig(p.Config, p.AppKey) {
		return nil, ErrInvalid
	}
	if len(p.Manifest) > MaxPayload {
		return nil, ErrInvalid
	}
	raw, e := b64(p.Manifest)
	if e != nil {
		return nil, ErrInvalid
	}
	var m struct {
		Files []manifestFile `json:"files"`
	}
	if strict(raw, &m) != nil || len(m.Files) == 0 || len(m.Files) > 65535 {
		return nil, ErrInvalid
	}
	var shape struct {
		Files []map[string]json.RawMessage `json:"files"`
	}
	if json.Unmarshal(raw, &shape) != nil {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	metadata := 0
	for i, f := range m.Files {
		// The path is a fixed eight-digit index, never an arbitrary filesystem path.
		digits := []byte("00000000.agc")
		n := i
		for j := 7; j >= 0; j-- {
			digits[j] = byte('0' + n%10)
			n /= 10
		}
		if len(f.Name) > 128 || !namePattern.MatchString(f.Name) || seen[f.Name] || f.Path != string(digits) || f.Size < 0 || f.Size > math.MaxInt64/2 || f.ChunkSize != 1048576 {
			return nil, ErrInvalid
		}
		seen[f.Name] = true
		switch f.Kind {
		case "watermark":
			if len(shape.Files[i]) != 6 || p.V != 2 || f.Name != "__authgo_watermark" || f.Encoding != "raw" || f.Size < 1 || f.Size > 8<<20 || f.PythonVersion != "" || f.MainClass != "" || f.Architecture != "" {
				return nil, ErrInvalid
			}
			metadata++
		case "python", "php", "dotnet":
			if f.Encoding != "tar" {
				return nil, ErrInvalid
			}
		case "node", "java", "protect":
			if f.Encoding != "raw" {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		if f.Kind == "python" && f.PythonVersion == "" || f.Kind == "protect" && f.Architecture != "amd64" && f.Architecture != "arm64" {
			return nil, ErrInvalid
		}
	}
	if metadata != 1 || len(m.Files) < 2 {
		return nil, ErrInvalid
	}
	a := []byte(fmt.Sprintf("authgo-payload-envelope-v%d\x00", p.V))
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID, p.Config} {
		a = lp(a, s)
	}
	h := sha256.Sum256(raw)
	return append(a, h[:]...), nil
}
func gcm(key []byte) (cipher.AEAD, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrInvalid
	}
	return cipher.NewGCM(b)
}
func OpenEnvelope(p Payload, private []byte) ([]byte, error) {
	a, e := p.aad()
	if e != nil {
		return nil, ErrInvalid
	}
	priv, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, ErrInvalid
	}
	ep, e := b64(p.Envelope.E)
	if e != nil || len(ep) != 32 {
		return nil, ErrInvalid
	}
	pub, e := ecdh.X25519().NewPublicKey(ep)
	if e != nil {
		return nil, ErrInvalid
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		return nil, ErrInvalid
	}
	defer clear(shared)
	a = append(a, ep...)
	salt := sha256.Sum256(a)
	kek, e := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/wrap", 32)
	if e != nil {
		return nil, ErrInvalid
	}
	defer clear(kek)
	n, e := b64(p.Envelope.N)
	if e != nil || len(n) != 12 {
		return nil, ErrInvalid
	}
	c, e := b64(p.Envelope.C)
	if e != nil || len(c) != 48 {
		return nil, ErrInvalid
	}
	g, _ := gcm(kek)
	key, e := g.Open(nil, n, c, a)
	if e != nil || len(key) != 32 {
		return nil, ErrInvalid
	}
	return key, nil
}

// Rewrap uses fresh server randomness; the client public key and challenge are
// fixed-width raw bytes in the AAD, not their base64 spellings. Config is excluded.
func Rewrap(p Payload, key []byte, ephemeral, challenge string) (Envelope, error) {
	return rewrap(p, key, ephemeral, challenge, rand.Reader)
}
func rewrap(p Payload, key []byte, ephemeral, challenge string, random io.Reader) (Envelope, error) {
	bad := Envelope{}
	if len(key) != 32 {
		return bad, ErrInvalid
	}
	ep, e := b64(ephemeral)
	if e != nil || len(ep) != 32 {
		return bad, ErrInvalid
	}
	ch, e := b64(challenge)
	if e != nil || len(ch) != 32 {
		return bad, ErrInvalid
	}
	pub, e := ecdh.X25519().NewPublicKey(ep)
	if e != nil {
		return bad, ErrInvalid
	}
	scalar := make([]byte, 32)
	if _, e = io.ReadFull(random, scalar); e != nil {
		return bad, e
	}
	defer clear(scalar)
	priv, e := ecdh.X25519().NewPrivateKey(scalar)
	if e != nil {
		return bad, ErrInvalid
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		return bad, ErrInvalid
	}
	defer clear(shared)
	a, e := rewrapAAD(p, ep, ch)
	if e != nil {
		return bad, e
	}
	salt := sha256.Sum256(a)
	kek, e := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/rewrap", 32)
	if e != nil {
		return bad, ErrInvalid
	}
	defer clear(kek)
	nonce := make([]byte, 12)
	if _, e = io.ReadFull(random, nonce); e != nil {
		return bad, e
	}
	g, _ := gcm(kek)
	enc := base64.RawURLEncoding.EncodeToString
	return Envelope{enc(priv.PublicKey().Bytes()), enc(nonce), enc(g.Seal(nil, nonce, key, a))}, nil
}
func rewrapAAD(p Payload, ep, ch []byte) ([]byte, error) {
	raw, e := b64(p.Manifest)
	if e != nil {
		return nil, ErrInvalid
	}
	h := sha256.Sum256(raw)
	a := []byte(fmt.Sprintf("authgo-payload-rewrap-v%d\x00", p.V))
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID} {
		a = lp(a, s)
	}
	a = append(a, h[:]...)
	a = append(a, ep...)
	return append(a, ch...), nil
}
