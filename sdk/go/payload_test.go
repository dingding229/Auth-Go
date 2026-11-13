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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func payloadVector(t *testing.T) (Payload, []byte, map[string]json.RawMessage) {
	t.Helper()
	raw, e := os.ReadFile("../vectors/payload-envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	var values map[string]json.RawMessage
	if e = json.Unmarshal(raw, &values); e != nil {
		t.Fatal(e)
	}
	p, e := ParsePayload(values["payload"])
	if e != nil {
		t.Fatal(e)
	}
	var text string
	json.Unmarshal(values["content_key_hex"], &text)
	key, e := hex.DecodeString(text)
	if e != nil {
		t.Fatal(e)
	}
	return p, key, values
}
func payloadTestMaterial(key []byte) []byte {
	return append(append([]byte{}, key...), bytes.Repeat([]byte{0x19}, 32)...)
}

func payloadTLSFixture(t *testing.T) (*signedServer, *Client, Payload, []byte) {
	t.Helper()
	s := newSignedServer(t)
	s.server.Close()
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	c := s.client(t)
	c.HTTPClient = s.server.Client()
	p, key, _ := payloadVector(t)
	s.payloadResponse = func(raw json.RawMessage, data map[string]any) string {
		var in struct {
			Payload   Payload `json:"payload"`
			Ephemeral string  `json:"ephemeral_public_key"`
			Challenge string  `json:"challenge"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return PayloadInvalid
		}
		got, e := in.Payload.PayloadBinding()
		want, _ := p.PayloadBinding()
		if e != nil || !bytes.Equal(got, want) {
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
		ch, _ := payloadB64.DecodeString(in.Challenge)
		aad, _ := payloadRewrapAAD(in.Payload, ep, ch)
		salt := sha256.Sum256(aad)
		kek := wire.HKDF(shared, salt[:], []byte("authgo/payload/v1/rewrap"), 32)
		b, _ := aes.NewCipher(kek)
		g, _ := cipher.NewGCM(b)
		n := make([]byte, 12)
		rand.Read(n)
		data["watermark"] = strings.Repeat("19", 32)
		data["e"] = payloadB64.EncodeToString(private.PublicKey().Bytes())
		data["n"] = payloadB64.EncodeToString(n)
		data["c"] = payloadB64.EncodeToString(g.Seal(nil, n, key, aad))
		return ""
	}
	return s, c, p, key
}
func payloadPaths(t *testing.T, c *Client) []string {
	t.Helper()
	files, e := filepath.Glob(filepath.Join(c.CacheDir, "authgo-payload-v2-*.cache"))
	if e != nil {
		t.Fatal(e)
	}
	return files
}
func TestPayloadUnlockRequiresCheckAndUsesAuthenticatedChannel(t *testing.T) {
	s, c, p, want := payloadTLSFixture(t)
	ctx := context.Background()
	if _, e := c.UnlockPayload(ctx, p); !errors.Is(e, ErrNotActivated) {
		t.Fatal(e)
	}
	if s.counts["payload.unlock"] != 0 {
		t.Fatal("implicit activation/unlock")
	}
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	got, e := c.UnlockPayload(ctx, p)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("unlock failed", e)
	}
	clear(got)
	if s.counts["payload.unlock"] != 1 || len(payloadPaths(t, c)) != 1 {
		t.Fatal("request/cache missing")
	}
	raw, _ := os.ReadFile(payloadPaths(t, c)[0])
	if !bytes.HasPrefix(raw, []byte(payloadCachePrefix)) || bytes.Contains(raw, want) || bytes.Contains(raw, []byte(payloadB64.EncodeToString(want))) || strings.Contains(payloadPaths(t, c)[0], testKey) {
		t.Fatal("plaintext key/license leaked")
	}
}
func TestPayloadCachedGraceRestartsAndExactExpiry(t *testing.T) {
	s, c, p, want := payloadTLSFixture(t)
	ctx := context.Background()
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	if _, e := c.UnlockPayload(ctx, p); e != nil {
		t.Fatal(e)
	}
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	fresh.now = s.clock.now
	if _, e := fresh.UnlockPayload(ctx, p); !errors.Is(e, ErrNotActivated) {
		t.Fatal("unverified restored proof used", e)
	}
	s.clock.add(5 * time.Minute)
	r, e := fresh.Check(ctx, testKey)
	if e != nil || r.Availability != "grace" {
		t.Fatal(e)
	}
	got, e := fresh.UnlockPayload(ctx, p)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("grace cache lost", e)
	}
	s.clock.add(55 * time.Minute)
	if _, e := fresh.UnlockPayload(ctx, p); !errors.Is(e, ErrGraceExpired) {
		t.Fatal("cache exceeded signed grace", e)
	}
}
func TestPayloadRefusalsClearOnlyPayloadInvalidPreserves(t *testing.T) {
	for _, code := range []string{LicenseRevoked, MaintenanceExpired, VersionDisabled, InstanceReplaced, PayloadInvalid} {
		t.Run(code, func(t *testing.T) {
			s, c, p, want := payloadTLSFixture(t)
			ctx := context.Background()
			if _, e := c.Check(ctx, testKey); e != nil {
				t.Fatal(e)
			}
			if _, e := c.UnlockPayload(ctx, p); e != nil {
				t.Fatal(e)
			}
			before := append([]byte{}, c.state.Proof.Envelope...)
			s.mu.Lock()
			s.responseCode = code
			s.mu.Unlock()
			key, e := c.UnlockPayload(ctx, p)
			if code == PayloadInvalid {
				if e != nil || !bytes.Equal(key, want) || len(payloadPaths(t, c)) != 1 || !bytes.Equal(c.state.Proof.Envelope, before) || c.state.Refused {
					t.Fatal("payload invalid destroyed licensing/cache", e)
				}
				return
			}
			if key != nil || e == nil || len(payloadPaths(t, c)) != 0 {
				t.Fatal("refusal retained key", e)
			}
			c.HTTPClient = unavailable()
			if key, e = c.UnlockPayload(ctx, p); key != nil || e == nil {
				t.Fatal("refusal resurrected cached key")
			}
		})
	}
	// A refusal on ordinary Verify/Heartbeat must clear the new files too.
	s, c, p, _ := payloadTLSFixture(t)
	if _, e := c.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	c.UnlockPayload(context.Background(), p)
	s.mode = "suspended"
	if _, e := c.Verify(context.Background()); e == nil || len(payloadPaths(t, c)) != 0 {
		t.Fatal("verify refusal kept payload keys", e)
	}
}
func TestPayloadTrialZeroGraceAndUnwritableDirectory(t *testing.T) {
	for _, trial := range []bool{true, false} {
		t.Run(map[bool]string{true: "trial", false: "zero-grace"}[trial], func(t *testing.T) {
			s, c, p, _ := payloadTLSFixture(t)
			s.trial = trial
			if !trial {
				duration := time.Duration(0)
				s.floating = true
				s.floatingGrace = &duration
			}
			if _, e := c.Check(context.Background(), testKey); e != nil {
				t.Fatal(e)
			}
			if _, e := c.UnlockPayload(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			if len(payloadPaths(t, c)) != 0 {
				t.Fatal("trial/zero grace wrote content key")
			}
			c.HTTPClient = unavailable()
			if _, e := c.UnlockPayload(context.Background(), p); e == nil {
				t.Fatal("trial/no grace ran offline")
			}
		})
	}
	s, c, p, want := payloadTLSFixture(t)
	if _, e := c.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	// /proc is non-writable even when the Go test toolchain runs as root.
	c.CacheDir = "/proc/authgo-cannot-create"
	key, e := c.UnlockPayload(context.Background(), p)
	if e != nil || !bytes.Equal(key, want) {
		t.Fatal("unwritable payload cache blocked online use", e)
	}
	_ = s
}
func TestPayloadCacheCannotMoveToDifferentInstance(t *testing.T) {
	s, c, p, _ := payloadTLSFixture(t)
	c.FingerprintFunc = nil
	t.Setenv("AUTHGO_INSTANCE_ID", "cache-instance-A")
	c.FingerprintFunc = func() (string, error) { return instanceFingerprint(os.Getenv("AUTHGO_INSTANCE_ID")), nil }
	if _, e := c.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	if _, e := c.UnlockPayload(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	source, _ := os.ReadFile(payloadPaths(t, c)[0])
	other := s.client(t)
	other.HTTPClient = s.server.Client()
	other.FingerprintFunc = func() (string, error) { return instanceFingerprint(os.Getenv("AUTHGO_INSTANCE_ID")), nil }
	t.Setenv("AUTHGO_INSTANCE_ID", "cache-instance-B")
	r, e := other.Check(context.Background(), testKey)
	if e != nil {
		t.Fatal(e)
	}
	path, _, _, e := other.payloadCacheMaterial(p, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, source, 0600); e != nil {
		t.Fatal(e)
	}
	other.HTTPClient = unavailable()
	if _, e = other.UnlockPayload(context.Background(), p); e == nil {
		t.Fatal("copied key cache crossed instance")
	}
}
func TestPayloadWireVectorsAndStreaming(t *testing.T) {
	p, key, values := payloadVector(t)
	bind, e := p.PayloadBinding()
	var want string
	json.Unmarshal(values["binding_hex"], &want)
	if e != nil || hex.EncodeToString(bind) != want {
		t.Fatal("pack binding mismatch", e)
	}
	var chunks []struct {
		File   int    `json:"file"`
		Chunk  int    `json:"chunk"`
		Nonce  string `json:"nonce_hex"`
		AAD    string `json:"aad_hex"`
		Cipher string `json:"cipher_hex"`
		Hash   string `json:"cipher_sha256_hex"`
		First  string `json:"cipher_first32_hex"`
		Tag    string `json:"tag_hex"`
	}
	json.Unmarshal(values["chunks"], &chunks)
	decode := func(text string) []byte {
		raw, e := hex.DecodeString(text)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	first := g.Seal(nil, decode(chunks[1].Nonce), bytes.Repeat([]byte{'A'}, PayloadChunkSize), decode(chunks[1].AAD))
	hash := sha256.Sum256(first)
	if hex.EncodeToString(hash[:]) != chunks[1].Hash || hex.EncodeToString(first[:32]) != chunks[1].First || hex.EncodeToString(first[len(first)-16:]) != chunks[1].Tag {
		t.Fatal("chunk vector mismatch")
	}
	ct := append(first, decode(chunks[2].Cipher)...)
	var plain bytes.Buffer
	if e = DecryptPayloadFile(&plain, bytes.NewReader(ct), int64(len(ct)), p, key, 1); e != nil || !bytes.Equal(plain.Bytes(), append(bytes.Repeat([]byte{'A'}, PayloadChunkSize), []byte("hello")...)) {
		t.Fatal("stream decrypt", e)
	}
	for _, bad := range [][]byte{ct[:len(ct)-1], append(append([]byte{}, ct...), 0)} {
		if e = DecryptPayloadFile(io.Discard, bytes.NewReader(bad), int64(len(bad)), p, key, 1); e == nil {
			t.Fatal("length tampering accepted")
		}
	}
	for _, q := range []Payload{func() Payload { q := p; q.Config += "A"; return q }(), func() Payload { q := p; q.Version = "9.0.0"; return q }()} {
		if e = DecryptPayloadFile(io.Discard, bytes.NewReader(ct), int64(len(ct)), q, key, 1); e == nil {
			t.Fatal("metadata tampering accepted")
		}
	}
	raw, e := os.ReadFile("../vectors/payload-unlock-v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Payload   Payload         `json:"payload"`
		Private   string          `json:"client_private_hex"`
		Challenge string          `json:"challenge_hex"`
		Response  PayloadEnvelope `json:"response"`
		AAD       string          `json:"rewrap_aad_hex"`
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vector")
	}
	private, e := ecdh.X25519().NewPrivateKey(decode(v.Private))
	if e != nil {
		t.Fatal(e)
	}
	got, e := unwrapPayload(v.Payload, v.Response, private, decode(v.Challenge))
	if e != nil || !bytes.Equal(got, key) {
		t.Fatal("rewrap vector", e)
	}
	aad, e := payloadRewrapAAD(v.Payload, private.PublicKey().Bytes(), decode(v.Challenge))
	if e != nil || hex.EncodeToString(aad) != v.AAD {
		t.Fatal("rewrap AAD")
	}
	changed := decode(v.Challenge)
	changed[0] ^= 1
	if _, e = unwrapPayload(v.Payload, v.Response, private, changed); e == nil {
		t.Fatal("challenge tampering")
	}
}
