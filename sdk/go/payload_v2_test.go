package sdk

import (
	"authgo/sdk/wire"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const payloadV2Tag = "0123456789abcdef0123456789abcdef"

func payloadV2Index(t *testing.T, offsets []string) []byte {
	t.Helper()
	if offsets == nil {
		offsets = []string{"0", "96", "192", "288", "384", "480", "576", "672"}
	}
	raw, e := json.Marshal(payloadWatermarkIndex{V: "1", Tag: payloadV2Tag, Files: []payloadWatermarkFile{{Index: "0", Entries: []payloadWatermarkEntry{{Path: []string{}, Offsets: offsets}}}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func payloadV2Fixture(t *testing.T, p Payload) Payload {
	t.Helper()
	p.V = 2
	raw, e := json.Marshal(PayloadManifest{Files: []PayloadFile{
		{Name: "main", Kind: "protect", Encoding: "raw", Architecture: runtime.GOARCH, Path: "00000000.agc", Size: 8 * payloadSlotSize, ChunkSize: PayloadChunkSize},
		{Name: "__authgo_watermark", Kind: "watermark", Encoding: "raw", Path: "00000001.agc", Size: int64(len(payloadV2Index(t, nil))), ChunkSize: PayloadChunkSize},
	}})
	if e != nil {
		t.Fatal(e)
	}
	p.Manifest = payloadB64.EncodeToString(raw)
	return p
}
func payloadV2TLSFixture(t *testing.T) (*signedServer, *Client, Payload, []byte) {
	t.Helper()
	s, c, p, key := payloadTLSFixture(t)
	p = payloadV2Fixture(t, p)
	wm := bytes.Repeat([]byte{0x19}, 32)
	s.payloadResponse = func(raw json.RawMessage, data map[string]any) string {
		var in struct {
			Payload   Payload `json:"payload"`
			Ephemeral string  `json:"ephemeral_public_key"`
			Challenge string  `json:"challenge"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return PayloadInvalid
		}
		want, e := p.PayloadBinding()
		got, err := in.Payload.PayloadBinding()
		if e != nil || err != nil || !bytes.Equal(got, want) {
			return PayloadInvalid
		}
		ep, e := payloadB64.DecodeString(in.Ephemeral)
		if e != nil {
			return PayloadInvalid
		}
		pub, e := ecdh.X25519().NewPublicKey(ep)
		if e != nil {
			return PayloadInvalid
		}
		private, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return InternalError
		}
		shared, e := private.ECDH(pub)
		if e != nil {
			return PayloadInvalid
		}
		defer clear(shared)
		ch, e := payloadB64.DecodeString(in.Challenge)
		if e != nil {
			return PayloadInvalid
		}
		aad, e := payloadRewrapAAD(in.Payload, ep, ch)
		if e != nil {
			return PayloadInvalid
		}
		salt := sha256.Sum256(aad)
		kek := wire.HKDF(shared, salt[:], []byte("authgo/payload/v1/rewrap"), 32)
		defer clear(kek)
		b, _ := aes.NewCipher(kek)
		g, _ := cipher.NewGCM(b)
		n := make([]byte, 12)
		if _, e = rand.Read(n); e != nil {
			return InternalError
		}
		data["e"] = payloadB64.EncodeToString(private.PublicKey().Bytes())
		data["n"] = payloadB64.EncodeToString(n)
		data["c"] = payloadB64.EncodeToString(g.Seal(nil, n, key, aad))
		data["watermark"] = hex.EncodeToString(wm)
		return ""
	}
	return s, c, p, append(append([]byte(nil), key...), wm...)
}

func TestPayloadV2ManifestStrict(t *testing.T) {
	base, _, _ := payloadVector(t)
	p := payloadV2Fixture(t, base)
	raw, _ := json.Marshal(p)
	if _, e := ParsePayload(raw); e != nil {
		t.Fatal(e)
	}
	aad, e := p.payloadAAD()
	if e != nil || !bytes.HasPrefix(aad, []byte("authgo-payload-envelope-v2\x00")) {
		t.Fatal("v2 envelope AAD", e)
	}
	rw, e := payloadRewrapAAD(p, make([]byte, 32), make([]byte, 32))
	if e != nil || !bytes.HasPrefix(rw, []byte("authgo-payload-rewrap-v2\x00")) {
		t.Fatal("v2 rewrap AAD", e)
	}
	manifest, _ := payloadB64.DecodeString(p.Manifest)
	files, _ := p.Files()
	meta, _ := json.Marshal(files[1])
	for name, change := range map[string]func() []byte{
		"missing":    func() []byte { b, _ := json.Marshal(PayloadManifest{Files: files[:1]}); return b },
		"alias-name": func() []byte { return bytes.Replace(manifest, []byte("__authgo_watermark"), []byte("watermark"), 1) },
		"reserved-code": func() []byte {
			return bytes.Replace(manifest, []byte(`"kind":"watermark"`), []byte(`"kind":"node"`), 1)
		},
		"empty": func() []byte {
			return bytes.Replace(manifest, []byte(fmt.Sprintf(`"size":%d`, files[1].Size)), []byte(`"size":0`), 1)
		},
		"too-large": func() []byte {
			return bytes.Replace(manifest, []byte(fmt.Sprintf(`"size":%d`, files[1].Size)), []byte(fmt.Sprintf(`"size":%d`, payloadMaxManifest+1)), 1)
		},
		"extra-optional": func() []byte {
			return bytes.Replace(manifest, meta, append(append([]byte(nil), meta[:len(meta)-1]...), []byte(`,"main_class":""}`)...), 1)
		},
		"alias-key": func() []byte {
			return bytes.Replace(manifest, []byte(`"kind":"watermark"`), []byte(`"Kind":"watermark"`), 1)
		},
		"duplicate-key": func() []byte {
			return bytes.Replace(manifest, []byte(`"kind":"watermark"`), []byte(`"kind":"watermark","kind":"watermark"`), 1)
		},
		"extra-key": func() []byte {
			return bytes.Replace(manifest, meta, append(append([]byte(nil), meta[:len(meta)-1]...), []byte(`,"slot_index":{}}`)...), 1)
		},
		"two-meta": func() []byte {
			copyFiles := append([]PayloadFile(nil), files...)
			next := files[1]
			next.Path = "00000002.agc"
			copyFiles = append(copyFiles, next)
			b, _ := json.Marshal(PayloadManifest{Files: copyFiles})
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.Manifest = payloadB64.EncodeToString(change())
			b, _ := json.Marshal(q)
			if _, e := ParsePayload(b); e == nil {
				t.Fatal("invalid v2 manifest accepted")
			}
		})
	}
	// Domain separation is not just the public version number.
	q := p
	q.V = 99
	if _, e := q.PayloadBinding(); e == nil {
		t.Fatal("unsupported payload version accepted")
	}
}

func TestPayloadV2PrivateIndexStrict(t *testing.T) {
	base, _, _ := payloadVector(t)
	p := payloadV2Fixture(t, base)
	files, _ := p.Files()
	valid := payloadV2Index(t, nil)
	if _, e := parsePayloadWatermarkIndex(valid, files); e != nil {
		t.Fatal(e)
	}
	for name, raw := range map[string][]byte{
		"number-version":   bytes.Replace(valid, []byte(`"v":"1"`), []byte(`"v":1`), 1),
		"number-index":     bytes.Replace(valid, []byte(`"index":"0"`), []byte(`"index":0`), 1),
		"leading-index":    bytes.Replace(valid, []byte(`"index":"0"`), []byte(`"index":"00"`), 1),
		"index-bound":      bytes.Replace(valid, []byte(`"index":"0"`), []byte(`"index":"65535"`), 1),
		"meta-index":       bytes.Replace(valid, []byte(`"index":"0"`), []byte(`"index":"1"`), 1),
		"missing-code":     bytes.Replace(valid, []byte(`"files":[`), []byte(`"files":[] , "extra":[`), 1),
		"tag-case":         bytes.Replace(valid, []byte(payloadV2Tag), []byte(strings.ToUpper(payloadV2Tag)), 1),
		"tag-short":        bytes.Replace(valid, []byte(payloadV2Tag), []byte("abcd"), 1),
		"alias":            bytes.Replace(valid, []byte(`"offsets"`), []byte(`"Offsets"`), 1),
		"unknown":          bytes.Replace(valid, []byte(`"v":"1"`), []byte(`"v":"1","unknown":true`), 1),
		"duplicate":        bytes.Replace(valid, []byte(`"v":"1"`), []byte(`"v":"1","v":"1"`), 1),
		"missing-tag":      bytes.Replace(valid, []byte(`"tag":"`+payloadV2Tag+`",`), nil, 1),
		"null-path":        bytes.Replace(valid, []byte(`"path":[]`), []byte(`"path":null`), 1),
		"raw-path":         bytes.Replace(valid, []byte(`"path":[]`), []byte(`"path":["main"]`), 1),
		"leading-offset":   bytes.Replace(valid, []byte(`"0","96"`), []byte(`"00","96"`), 1),
		"number-offset":    bytes.Replace(valid, []byte(`"0","96"`), []byte(`0,"96"`), 1),
		"negative":         bytes.Replace(valid, []byte(`"0","96"`), []byte(`"-1","96"`), 1),
		"overlap":          payloadV2Index(t, []string{"0", "95", "192", "288", "384", "480", "576", "672"}),
		"unsorted":         payloadV2Index(t, []string{"96", "0", "192", "288", "384", "480", "576", "672"}),
		"duplicate-offset": payloadV2Index(t, []string{"0", "0", "192", "288", "384", "480", "576", "672"}),
		"short":            payloadV2Index(t, []string{"0", "96", "192", "288", "384", "480", "576"}),
		"past-end":         payloadV2Index(t, []string{"0", "96", "192", "288", "384", "480", "576", "673"}),
		"overflow":         payloadV2Index(t, []string{"0", "96", "192", "288", "384", "480", "576", strconv.FormatInt(math.MaxInt64/2+1, 10)}),
		"oversize-json":    bytes.Repeat([]byte{' '}, payloadMaxManifest+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
				t.Fatal("bad index accepted")
			}
		})
	}
	var decoded payloadWatermarkIndex
	if payloadJSON(valid, &decoded) != nil {
		t.Fatal("fixture")
	}
	decoded.Files = append(decoded.Files, decoded.Files[0])
	raw, _ := json.Marshal(decoded)
	if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
		t.Fatal("duplicate file accepted")
	}
	decoded.Files = decoded.Files[:1]
	decoded.Files[0].Entries = append(decoded.Files[0].Entries, decoded.Files[0].Entries[0])
	raw, _ = json.Marshal(decoded)
	if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
		t.Fatal("duplicate entry accepted")
	}
	more := append([]PayloadFile(nil), files...)
	more = append(more, files[0])
	if _, e := parsePayloadWatermarkIndex(valid, more); e == nil {
		t.Fatal("uncovered code accepted")
	}
}

func TestPayloadV2ArchiveIndexPathsAndGlobalCaps(t *testing.T) {
	base, _, _ := payloadVector(t)
	p := payloadV2Fixture(t, base)
	baseFiles, _ := p.Files()
	var index payloadWatermarkIndex
	payloadJSON(payloadV2Index(t, nil), &index)
	for _, kind := range []string{"python", "php", "java", "dotnet"} {
		files := append([]PayloadFile(nil), baseFiles...)
		files[0].Kind = kind
		for _, names := range [][]string{{"module.dll"}, {"../evil"}, {"/abs"}, {"a\\b"}, {"a/../b"}, {"."}, {"a//b"}, {"a:b"}, {"a\x00b"}, {"a\nb"}, {"a/"}, {"\ufffd"}, {"outer.jar", "a.class"}} {
			index.Files[0].Entries[0].Path = names
			raw, _ := json.Marshal(index)
			_, e := parsePayloadWatermarkIndex(raw, files)
			valid := len(names) == 1 && (names[0] == "module.dll" || names[0] == "\ufffd" && kind != "dotnet") || kind == "java" && len(names) == 2
			if (e == nil) != valid {
				t.Fatalf("%s %q: %v", kind, names, e)
			}
		}
		index.Files[0].Entries[0].Path = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
		raw, _ := json.Marshal(index)
		if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
			t.Fatal("path depth accepted")
		}
	}
	files := append([]PayloadFile(nil), baseFiles...)
	files[0].Kind = "java"
	index.Files[0].Entries = []payloadWatermarkEntry{{Path: []string{"a.class"}, Offsets: []string{}}}
	for i := 0; i <= payloadIndexLimit; i++ {
		index.Files[0].Entries[0].Offsets = append(index.Files[0].Entries[0].Offsets, strconv.Itoa(i*payloadSlotSize))
	}
	raw, _ := json.Marshal(index)
	if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
		t.Fatal("offset cap accepted")
	}
	index.Files[0].Entries = make([]payloadWatermarkEntry, payloadIndexLimit+1)
	raw, _ = json.Marshal(index)
	if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
		t.Fatal("entry cap accepted")
	}
	index.Files = make([]payloadWatermarkFile, payloadIndexLimit+1)
	raw, _ = json.Marshal(index)
	if _, e := parsePayloadWatermarkIndex(raw, files); e == nil {
		t.Fatal("file cap accepted")
	}
}

func TestPayloadV2UnlockMaterialAndTerminalWatermark(t *testing.T) {
	for _, bad := range []any{nil, "", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("1", 63), strings.Repeat("1", 65), strings.Repeat("g", 64), 1, []string{"x"}} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			s, c, p, want := payloadV2TLSFixture(t)
			if _, e := c.Check(context.Background(), testKey); e != nil {
				t.Fatal(e)
			}
			material, e := c.unlockPayloadMaterial(context.Background(), p)
			if e != nil || !bytes.Equal(material, want) {
				t.Fatal("material", e)
			}
			clear(material)
			key, e := c.UnlockPayload(context.Background(), p)
			if e != nil || len(key) != 32 || cap(key) != 32 || !bytes.Equal(key, want[:32]) {
				t.Fatal("public compatibility", e)
			}
			clear(key)
			valid := s.payloadResponse
			s.mu.Lock()
			s.payloadResponse = func(raw json.RawMessage, data map[string]any) string {
				code := valid(raw, data)
				if bad == nil {
					delete(data, "watermark")
				} else {
					data["watermark"] = bad
				}
				return code
			}
			s.mu.Unlock()
			material, e = c.unlockPayloadMaterial(context.Background(), p)
			var terminal *payloadWatermarkError
			if material != nil || !errors.As(e, &terminal) {
				t.Fatal("bad WM fell back to cached material", e)
			}
		})
	}
}

func TestPayloadV2PostSignatureWatermarkTamperRejectedWithoutCache(t *testing.T) {
	for _, api := range []string{"private-material", "public-key"} {
		t.Run(api, func(t *testing.T) {
			s, c, p, want := payloadV2TLSFixture(t)
			ctx := context.Background()
			if _, e := c.Check(ctx, testKey); e != nil {
				t.Fatal(e)
			}
			paths, e := filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v*-*.cache"))
			if e != nil || len(paths) != 0 {
				t.Fatal("expected cold payload cache", paths, e)
			}
			s.mu.Lock()
			s.mode = "watermark-tamper"
			before := s.counts["payload.unlock"]
			s.mu.Unlock()
			var material []byte
			if api == "public-key" {
				material, e = c.UnlockPayload(ctx, p)
			} else {
				material, e = c.unlockPayloadMaterial(ctx, p)
			}
			if material != nil || !errors.Is(e, ErrResponseSignatureInvalid) {
				t.Fatal("post-signature valid watermark mutation was not rejected by signature", e)
			}
			paths, e = filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v*-*.cache"))
			if e != nil || len(paths) != 0 {
				t.Fatal("tampered response populated payload cache", paths, e)
			}
			s.mu.Lock()
			calls := s.counts["payload.unlock"] - before
			s.mode = ""
			s.mu.Unlock()
			if calls != 1 {
				t.Fatal("expected an online payload unlock", calls)
			}
			material, e = c.unlockPayloadMaterial(ctx, p)
			if e != nil || !bytes.Equal(material, want) {
				t.Fatal("untampered signed watermark failed", e)
			}
			clear(material)
		})
	}
}

func TestPayloadV2WatermarkContextBeforeDecode(t *testing.T) {
	for _, mode := range []string{"bad-signature", "ticket-challenge", "wrong-nonce", "ticket-device", "old-ts"} {
		t.Run(mode, func(t *testing.T) {
			s, c, p, _ := payloadV2TLSFixture(t)
			if _, e := c.Check(context.Background(), testKey); e != nil {
				t.Fatal(e)
			}
			valid := s.payloadResponse
			s.mu.Lock()
			s.payloadResponse = func(raw json.RawMessage, data map[string]any) string {
				code := valid(raw, data)
				delete(data, "watermark")
				return code
			}
			s.mode = mode
			s.mu.Unlock()
			material, e := c.unlockPayloadMaterial(context.Background(), p)
			var terminal *payloadWatermarkError
			if material != nil || e == nil || errors.As(e, &terminal) {
				t.Fatal("WM decoded before authenticated context", e)
			}
		})
	}
}

func TestPayloadV2CacheMaterialLengthBindingAndProof(t *testing.T) {
	s, c, p, want := payloadV2TLSFixture(t)
	c.stubMode = true
	r, e := c.Check(context.Background(), testKey)
	if e != nil {
		t.Fatal(e)
	}
	material, e := c.unlockPayloadMaterial(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	clear(material)
	path, aead, aad, e := c.payloadCacheMaterial(p, r)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := os.ReadFile(path)
	if e != nil || !bytes.HasPrefix(encoded, []byte("AUTHGO-PAYLOAD-CACHE-v2.")) || !strings.HasPrefix(filepath.Base(path), "authgo-payload-v2-") {
		t.Fatal("v2 cache", e)
	}
	ct, e := payloadB64.DecodeString(string(encoded[len(payloadCacheFilePrefix(p)):]))
	if e != nil {
		t.Fatal(e)
	}
	got, e := aead.Open(nil, ct[:12], ct[12:], aad)
	if e != nil || !bytes.Equal(got, want) || !bytes.HasPrefix(aad, []byte("authgo-payload-cache-file-v2\x00")) {
		t.Fatal("cache material/AAD", e)
	}
	clear(got)
	for _, bad := range [][]byte{want[:32], want[:63], append(append([]byte(nil), want...), 0), append(append([]byte(nil), want[:32]...), make([]byte, 32)...)} {
		n := bytes.Repeat([]byte{0x31}, 12)
		sealed := []byte(payloadCacheFilePrefix(p) + payloadB64.EncodeToString(aead.Seal(n, n, bad, aad)))
		if e := os.WriteFile(path, sealed, 0600); e != nil {
			t.Fatal(e)
		}
		if got, e := c.loadPayloadKey(p, r); got != nil || e == nil {
			t.Fatal("wrong cache plaintext accepted")
		}
	}
	if e = os.WriteFile(path, encoded, 0600); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"binding", "manifest", "license"} {
		q := p
		proof := *r
		switch change {
		case "binding":
			b, _ := payloadB64.DecodeString(q.Envelope.C)
			b[0] ^= 1
			q.Envelope.C = payloadB64.EncodeToString(b)
		case "manifest":
			raw, _ := payloadB64.DecodeString(q.Manifest)
			q.Manifest = payloadB64.EncodeToString(bytes.Replace(raw, []byte(`"name":"main"`), []byte(`"name":"other"`), 1))
		case "license":
			g, _ := c.validateTicket(proof.ticket, true)
			g.LicenseID++
			proof.ticket, e = wire.EncodeTicket(g, s.private)
			if e != nil {
				t.Fatal(e)
			}
		}
		other, _, _, e := c.payloadCacheMaterial(q, &proof)
		if e != nil {
			t.Fatal(e)
		}
		if change != "license" && other == path {
			t.Fatal("filename lacks binding", change)
		}
		if e = os.WriteFile(other, encoded, 0600); e != nil {
			t.Fatal(e)
		}
		if got, e := c.loadPayloadKey(q, &proof); got != nil || e == nil {
			t.Fatal("cache moved across binding", change)
		}
	}
	if e = os.WriteFile(path, encoded, 0600); e != nil {
		t.Fatal(e)
	}
	restart := s.client(t)
	restart.CacheDir = c.CacheDir
	restart.stubMode = true
	restart.HTTPClient = unavailable()
	// The native proof path must recover all 64 bytes, not only the public key.
	if e = restart.online(""); e != nil {
		t.Fatal(e)
	}
	got, e = restart.protectedCachedKey(p)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("protected proof lost watermark", e)
	}
	clear(got)
	s.clock.add(time.Hour)
	if got, e = restart.protectedCachedKey(p); got != nil || e == nil {
		t.Fatal("proof crossed exact grace expiry")
	}
}

func TestPayloadV2RefusalClearsMaterial(t *testing.T) {
	for _, code := range []string{LicenseRevoked, MaintenanceExpired, VersionDisabled, InstanceReplaced, PayloadInvalid} {
		t.Run(code, func(t *testing.T) {
			s, c, p, want := payloadV2TLSFixture(t)
			c.stubMode = true
			r, e := c.Check(context.Background(), testKey)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = c.unlockPayloadMaterial(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			// Clear-all behavior covers two current builds, not two format versions.
			sibling := p
			sibling.Version = "1.2.4"
			c.savePayloadKey(sibling, r, want)
			paths, _ := filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v*-*.cache"))
			if len(paths) != 2 {
				t.Fatal("missing control caches")
			}
			s.mu.Lock()
			s.responseCode = code
			s.mu.Unlock()
			got, e := c.unlockPayloadMaterial(context.Background(), p)
			paths, _ = filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v*-*.cache"))
			if code == PayloadInvalid {
				if e != nil || !bytes.Equal(got, want) || len(paths) != 2 {
					t.Fatal("temporary refusal classification changed", e)
				}
				clear(got)
			} else if got != nil || e == nil || len(paths) != 0 {
				t.Fatal("explicit refusal retained cache", e)
			}
		})
	}
}

func TestPayloadV2CacheRejectsMalformedHeaderAndMovedIdentity(t *testing.T) {
	s, c, p, want := payloadV2TLSFixture(t)
	r, e := c.Check(context.Background(), testKey)
	if e != nil {
		t.Fatal(e)
	}
	c.savePayloadKey(p, r, want)
	path, aead, aad, e := c.payloadCacheMaterial(p, r)
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	malformed := bytes.Replace(original, []byte(payloadCachePrefix), []byte("INVALID-PAYLOAD-CACHE."), 1)
	if e = os.WriteFile(path, malformed, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := c.loadPayloadKey(p, r); got != nil || e == nil {
		t.Fatal("malformed cache header accepted")
	}
	// Incomplete material cannot be saved or silently padded into a watermark.
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	c.savePayloadKey(p, r, want[:32])
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("32-byte v2 material saved")
	}
	// Changing identity and obtaining a legitimately signed matching ticket still
	// must not make ciphertext copied from the old instance decryptable.
	oldFingerprint := c.fingerprint
	c.fingerprint = strings.Repeat("b", 64)
	g, e := wire.DecodeTicket(r.ticket, c.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	g.DeviceHash = sha([]byte(c.fingerprint))
	moved := *r
	moved.ticket, e = wire.EncodeTicket(g, s.private)
	if e != nil {
		t.Fatal(e)
	}
	other, _, _, e := c.payloadCacheMaterial(p, &moved)
	if e != nil {
		t.Fatal(e)
	}
	if other == path {
		t.Fatal("cache filename lacks identity")
	}
	if e = os.WriteFile(other, original, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := c.loadPayloadKey(p, &moved); got != nil || e == nil {
		t.Fatal("cache crossed instance identity")
	}
	c.fingerprint = oldFingerprint
	// Authenticate a 32-byte plaintext with otherwise correct v2 AAD: length is
	// independently rejected rather than relying only on GCM authentication.
	n := bytes.Repeat([]byte{0x44}, 12)
	sealed := []byte(payloadCacheFilePrefix(p) + payloadB64.EncodeToString(aead.Seal(n, n, want[:32], aad)))
	if e = os.WriteFile(path, sealed, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := c.loadPayloadKey(p, r); got != nil || e == nil {
		t.Fatal("K-only material admitted in v2 cache")
	}
}

func TestPayloadV2TrialOfflineAndNoCachePolicies(t *testing.T) {
	for _, policy := range []string{"trial", "zero-grace", "offline", "memory", "disabled"} {
		t.Run(policy, func(t *testing.T) {
			s, c, p, material := payloadV2TLSFixture(t)
			r, e := c.Check(context.Background(), testKey)
			if e != nil {
				t.Fatal(e)
			}
			g, e := c.validateTicket(r.ticket, true)
			if e != nil {
				t.Fatal(e)
			}
			switch policy {
			case "trial":
				g.IsTrial = true
				r.IsTrial = true
			case "zero-grace":
				g.GraceUntil = g.IssuedAt
			case "offline":
				r.Source = "offline"
			case "memory":
				c.memoryCache = true
			case "disabled":
				c.payloadNoCache = true
			}
			r.ticket, e = wire.EncodeTicket(g, s.private)
			if e != nil {
				t.Fatal(e)
			}
			c.savePayloadKey(p, r, material)
			if got, e := c.loadPayloadKey(p, r); got != nil || e == nil {
				t.Fatal("noncache policy weakened")
			}
			files, _ := filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v2-*.cache"))
			if len(files) != 0 {
				t.Fatal("noncache policy wrote material")
			}
		})
	}
}

func TestPayloadV2CachedGraceRestartsAndExactExpiry(t *testing.T) {
	s, c, p, want := payloadV2TLSFixture(t)
	ctx := context.Background()
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	if _, e := c.unlockPayloadMaterial(ctx, p); e != nil {
		t.Fatal(e)
	}
	restart := s.client(t)
	restart.CacheDir = c.CacheDir
	restart.HTTPClient = unavailable()
	s.clock.add(5 * time.Minute)
	r, e := restart.Check(ctx, testKey)
	if e != nil || r.Availability != "grace" {
		t.Fatal("grace restart", e)
	}
	material, e := restart.unlockPayloadMaterial(ctx, p)
	if e != nil || !bytes.Equal(material, want) {
		t.Fatal("cached unlock lost watermark", e)
	}
	clear(material)
	key, e := restart.UnlockPayload(ctx, p)
	if e != nil || !bytes.Equal(key, want[:32]) {
		t.Fatal("public cached key compatibility", e)
	}
	clear(key)
	s.clock.add(55 * time.Minute)
	if material, e := restart.unlockPayloadMaterial(ctx, p); material != nil || !errors.Is(e, ErrGraceExpired) {
		t.Fatal("v2 cache exceeded exact grace boundary", e)
	}
}

func TestPayloadV2OrdinaryVerifyRefusalClearsMaterial(t *testing.T) {
	s, c, p, material := payloadV2TLSFixture(t)
	c.stubMode = true
	r, e := c.Check(context.Background(), testKey)
	if e != nil {
		t.Fatal(e)
	}
	c.savePayloadKey(p, r, material)
	s.mu.Lock()
	s.responseCode = LicenseRevoked
	s.mu.Unlock()
	if _, e = c.Verify(context.Background()); !explicitRefusal(e) {
		t.Fatal("missing authenticated refusal", e)
	}
	paths, _ := filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v*-*.cache"))
	if len(paths) != 0 {
		t.Fatal("ordinary licensing refusal retained versioned material")
	}
	if _, e = os.Stat(c.payloadProofPath()); !os.IsNotExist(e) {
		t.Fatal("refusal retained shared proof", e)
	}
	clear(material)
}
