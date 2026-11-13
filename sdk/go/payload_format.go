package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const PayloadChunkSize = 1 << 20
const payloadMaxManifest = 8 << 20

var payloadInvalid = failure(PayloadInvalid, "加密载荷无效", nil)

type payloadBase64 struct{}

var payloadB64 payloadBase64

func (payloadBase64) EncodeToString(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
func (payloadBase64) DecodeString(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, payloadInvalid
	}
	return b, nil
}

var payloadNameRE = regexp.MustCompile(`^[a-z0-9_-]+$`)
var payloadSemverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// File describes one ciphertext stream. Size is the plaintext stream size,
// including tar framing for directories. Indexes are implicit array positions.
type PayloadFile struct {
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
type PayloadManifest struct {
	Files []PayloadFile `json:"files"`
}
type PayloadEnvelope struct {
	E string `json:"e"`
	N string `json:"n"`
	C string `json:"c"`
}
type Payload struct {
	V        int             `json:"v"`
	AppKey   string          `json:"app_key"`
	Version  string          `json:"version"`
	BuiltAt  string          `json:"built_at"`
	KeyID    string          `json:"key_id"`
	Config   string          `json:"config"`
	Manifest string          `json:"manifest"`
	Envelope PayloadEnvelope `json:"envelope"`
}

func payloadValidVersion(s string) bool {
	if len(s) > 256 || !payloadSemverRE.MatchString(s) {
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
func payloadLP(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}
func (p Payload) payloadAAD() ([]byte, error) {
	if p.V != 2 || len(p.AppKey) == 0 || len(p.AppKey) > 256 || !payloadNameRE.MatchString(p.KeyID) || len(p.KeyID) > 128 || !payloadValidVersion(p.Version) {
		return nil, payloadInvalid
	}
	t, e := time.Parse(time.RFC3339, p.BuiltAt)
	if e != nil || t.UTC().Format("2006-01-02T15:04:05Z") != p.BuiltAt {
		return nil, payloadInvalid
	}
	if err := payloadConfigValid(p.Config, p.AppKey); err != nil {
		return nil, payloadInvalid
	}
	raw, e := payloadB64.DecodeString(p.Manifest)
	if e != nil || len(raw) > payloadMaxManifest {
		return nil, payloadInvalid
	}
	if _, e = decodePayloadManifestVersion(raw, p.V); e != nil {
		return nil, e
	}
	a := []byte("authgo-payload-envelope-v2\x00")
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID, p.Config} {
		a = payloadLP(a, s)
	}
	h := sha256.Sum256(raw)
	return append(a, h[:]...), nil
}
func decodePayloadManifest(raw []byte) (PayloadManifest, error) {
	return decodePayloadManifestVersion(raw, 2)
}
func decodePayloadManifestVersion(raw []byte, version int) (PayloadManifest, error) {
	var m PayloadManifest
	if err := payloadJSON(raw, &m); err != nil || version != 2 || len(m.Files) == 0 || len(m.Files) > 65535 {
		return m, payloadInvalid
	}
	names := map[string]bool{}
	metadata := 0
	// Optional code-only fields must be ABSENT, not merely empty, on metadata.
	var shape struct {
		Files []map[string]json.RawMessage `json:"files"`
	}
	if json.Unmarshal(raw, &shape) != nil {
		return m, payloadInvalid
	}
	for i, f := range m.Files {
		if !payloadNameRE.MatchString(f.Name) || len(f.Name) > 128 || names[f.Name] || f.Path != fmt.Sprintf("%08d.agc", i) || f.Size < 0 || f.Size > math.MaxInt64/2 || f.ChunkSize != PayloadChunkSize {
			return m, payloadInvalid
		}
		names[f.Name] = true
		if f.Name == "__authgo_watermark" && f.Kind != "watermark" {
			return m, payloadInvalid
		}
		switch f.Kind {
		case "watermark":
			if version != 2 || f.Name != "__authgo_watermark" || f.Encoding != "raw" || f.Size == 0 || f.Size > payloadMaxManifest || len(shape.Files[i]) != 6 {
				return m, payloadInvalid
			}
			metadata++
		case "python", "php", "dotnet":
			if f.Encoding != "tar" {
				return m, payloadInvalid
			}
		case "node", "java", "protect":
			if f.Encoding != "raw" {
				return m, payloadInvalid
			}
		default:
			return m, payloadInvalid
		}
		if f.Kind == "python" && f.PythonVersion == "" {
			return m, payloadInvalid
		}
		if f.Kind == "protect" && f.Architecture != "amd64" && f.Architecture != "arm64" {
			return m, payloadInvalid
		}
	}
	if metadata != 1 || len(m.Files) < 2 {
		return m, payloadInvalid
	}
	return m, nil
}
func payloadJSON(raw []byte, out any) error {
	if _, e := canonicalizeJSON(raw); e != nil {
		return payloadInvalid
	}
	// Reject duplicate/unknown/case-aliased keys and missing required fields,
	// unlike encoding/json's otherwise case-insensitive struct field matching.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(reflect.Type, int) error
	value = func(typ reflect.Type, depth int) error {
		if depth > 64 {
			return payloadInvalid
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if token == nil && typ != nil && typ.Kind() != reflect.Slice && typ.Kind() != reflect.Map && typ.Kind() != reflect.Interface {
			return payloadInvalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			fields := map[string]reflect.StructField{}
			if typ != nil && typ.Kind() == reflect.Struct {
				for i := 0; i < typ.NumField(); i++ {
					f := typ.Field(i)
					fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f
				}
			}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return payloadInvalid
				}
				seen[name] = true
				var child reflect.Type
				if typ != nil && typ.Kind() == reflect.Struct {
					f, ok := fields[name]
					if !ok {
						return payloadInvalid
					}
					child = f.Type
				}
				if e = value(child, depth+1); e != nil {
					return e
				}
			}
			for name, f := range fields {
				if !seen[name] && !strings.Contains(f.Tag.Get("json"), ",omitempty") {
					return payloadInvalid
				}
			}
		case '[':
			var child reflect.Type
			if typ != nil && typ.Kind() == reflect.Slice {
				child = typ.Elem()
			}
			for d.More() {
				if e = value(child, depth+1); e != nil {
					return e
				}
			}
		default:
			return payloadInvalid
		}
		_, e = d.Token()
		return e
	}
	if e := value(reflect.TypeOf(out).Elem(), 0); e != nil {
		return payloadInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return payloadInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return payloadInvalid
	}
	return nil
}
func payloadConfigValid(s, app string) error {
	if len(s) > 32768 || !strings.HasPrefix(s, "authgo2.") {
		return payloadInvalid
	}
	raw, e := payloadB64.DecodeString(strings.TrimPrefix(s, "authgo2."))
	if e != nil {
		return payloadInvalid
	}
	var c struct {
		URL        string `json:"url"`
		AppKey     string `json:"app_key"`
		AppSecret  string `json:"app_secret"`
		PublicKey  string `json:"public_key"`
		GatewayKey string `json:"gateway_key"`
	}
	if payloadJSON(raw, &c) != nil || c.AppKey != app || c.AppSecret == "" {
		return payloadInvalid
	}
	https := func(s string) bool {
		u, e := url.Parse(s)
		return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
	}
	if !https(c.URL) {
		return payloadInvalid
	}
	pub, e := base64.StdEncoding.Strict().DecodeString(c.PublicKey)
	if e != nil || len(pub) != 32 {
		return payloadInvalid
	}
	gateway, e := payloadB64.DecodeString(c.GatewayKey)
	if e != nil || len(gateway) != 32 {
		return payloadInvalid
	}
	return nil
}

// ParsePayload validates the full original payload.json, preserving config and raw manifest bytes.
func ParsePayload(raw []byte) (Payload, error) {
	var p Payload
	if len(raw) > 65536 || payloadJSON(raw, &p) != nil {
		return p, payloadInvalid
	}
	if _, e := p.payloadAAD(); e != nil {
		return p, e
	}
	if _, e := p.PayloadBinding(); e != nil {
		return p, e
	}
	return p, nil
}
func (p Payload) PayloadBinding() ([]byte, error) {
	a, e := p.payloadAAD()
	if e != nil {
		return nil, e
	}
	for _, part := range []struct {
		s string
		n int
	}{{p.Envelope.E, 32}, {p.Envelope.N, 12}, {p.Envelope.C, 48}} {
		b, e := payloadB64.DecodeString(part.s)
		if e != nil || len(b) != part.n {
			return nil, payloadInvalid
		}
		a = append(a, b...)
	}
	h := sha256.Sum256(a)
	return h[:], nil
}
func (p Payload) Files() ([]PayloadFile, error) {
	if _, e := p.payloadAAD(); e != nil {
		return nil, e
	}
	raw, _ := payloadB64.DecodeString(p.Manifest)
	m, e := decodePayloadManifestVersion(raw, p.V)
	return m.Files, e
}
func PayloadCipherSize(size int64) int64 {
	return size + 16*max(int64(1), (size+PayloadChunkSize-1)/PayloadChunkSize)
}

// DecryptPayloadFile authenticates every chunk before writing it. Memory stays bounded by 1 MiB.
func DecryptPayloadFile(dst io.Writer, src io.ReaderAt, total int64, p Payload, key []byte, index int) error {
	files, e := p.Files()
	if e != nil || index < 0 || index >= len(files) || len(key) != 32 {
		return payloadInvalid
	}
	f := files[index]
	if total != PayloadCipherSize(f.Size) {
		return payloadInvalid
	}
	bind, e := p.PayloadBinding()
	if e != nil {
		return e
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return payloadInvalid
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return payloadInvalid
	}
	count := max(int64(1), (f.Size+PayloadChunkSize-1)/PayloadChunkSize)
	buffer := make([]byte, PayloadChunkSize+16)
	defer clear(buffer)
	for j := int64(0); j < count; j++ {
		n := min(int64(PayloadChunkSize), f.Size-j*PayloadChunkSize)
		ct := buffer[:n+16]
		read, e := src.ReadAt(ct, j*(PayloadChunkSize+16))
		if read != len(ct) || (e != nil && e != io.EOF) {
			return payloadInvalid
		}
		nonce := binary.BigEndian.AppendUint32(nil, uint32(index))
		nonce = binary.BigEndian.AppendUint64(nonce, uint64(j))
		aad := append([]byte("authgo-payload-chunk-v1\x00"), bind...)
		aad = binary.BigEndian.AppendUint32(aad, uint32(index))
		aad = binary.BigEndian.AppendUint64(aad, uint64(j))
		last := byte(0)
		if j == count-1 {
			last = 1
		}
		aad = append(aad, last)
		plain, e := g.Open(ct[:0], nonce, ct, aad)
		if e != nil {
			return payloadInvalid
		}
		wrote, e := dst.Write(plain)
		clear(plain)
		if e != nil {
			return e
		}
		if wrote != int(n) {
			return io.ErrShortWrite
		}
	}
	return nil
}
