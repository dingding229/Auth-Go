package payloadkey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func vector(t *testing.T) (Payload, map[string]json.RawMessage) {
	t.Helper()
	raw, e := os.ReadFile("../../../sdk/vectors/payload-envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]json.RawMessage
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	p, e := Parse(v["payload"])
	if e != nil {
		t.Fatal(e)
	}
	return p, v
}
func field(t *testing.T, v map[string]json.RawMessage, k string) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(v[k], &s); e != nil {
		t.Fatal(k, e)
	}
	return s
}
func TestPackVectorAndEveryEnvelopeBinding(t *testing.T) {
	p, v := vector(t)
	private := unhex(t, field(t, v, "recipient_private_hex"))
	want := unhex(t, field(t, v, "content_key_hex"))
	got, e := OpenEnvelope(p, private)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("pack interop", e)
	}
	cases := map[string]func(*Payload){
		"v": func(p *Payload) { p.V = 3 }, "app_key": func(p *Payload) { p.AppKey = "other" }, "version": func(p *Payload) { p.Version = "9.0.0" },
		"built_at": func(p *Payload) { p.BuiltAt = "2026-11-08T00:00:00Z" }, "key_id": func(p *Payload) { p.KeyID = "other" },
		"config": func(p *Payload) {
			raw, _ := b64(strings.TrimPrefix(p.Config, "authgo2."))
			raw = bytes.ReplaceAll(raw, []byte("https://"), []byte("https://other."))
			p.Config = "authgo2." + base64.RawURLEncoding.EncodeToString(raw)
		},
		"manifest": func(p *Payload) {
			raw, _ := b64(p.Manifest)
			p.Manifest = base64.RawURLEncoding.EncodeToString(append(raw, ' '))
		},
		"e": func(p *Payload) { p.Envelope.E = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) },
		"n": func(p *Payload) { p.Envelope.N = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 12)) },
		"c": func(p *Payload) { p.Envelope.C = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 48)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			if _, e := OpenEnvelope(q, private); e != ErrInvalid {
				t.Fatal("tampering accepted", e)
			}
		})
	}
}
func TestPayloadLimitsAndStrictFields(t *testing.T) {
	p, _ := vector(t)
	for name, change := range map[string]func(*Payload){"manifest": func(p *Payload) { p.Manifest = strings.Repeat("A", MaxPayload+1) }, "config": func(p *Payload) { p.Config = strings.Repeat("A", maxConfig+1) }} {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			raw, _ := json.Marshal(q)
			if _, e := Parse(raw); e != ErrInvalid {
				t.Fatal(e)
			}
		})
	}
	raw, _ := json.Marshal(p)
	for _, bad := range []string{strings.Replace(string(raw), `"v":2`, `"V":2`, 1), strings.Replace(string(raw), `"v":2`, `"v":2,"v":2`, 1), strings.Replace(string(raw), `"v":2,`, "", 1)} {
		if _, e := Parse([]byte(bad)); e != ErrInvalid {
			t.Fatal("invalid shape accepted")
		}
	}
}
func TestRewrapVector(t *testing.T) {
	raw, e := os.ReadFile("../../../sdk/vectors/payload-unlock-v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Payload       Payload  `json:"payload"`
		ContentKey    string   `json:"content_key_hex"`
		ClientPrivate string   `json:"client_private_hex"`
		ClientPublic  string   `json:"client_public_hex"`
		ServerPrivate string   `json:"server_private_hex"`
		ServerPublic  string   `json:"server_public_hex"`
		Challenge     string   `json:"challenge_hex"`
		AAD           string   `json:"rewrap_aad_hex"`
		Shared        string   `json:"shared_hex"`
		Salt          string   `json:"salt_hex"`
		KEK           string   `json:"kek_hex"`
		Nonce         string   `json:"nonce_hex"`
		Response      Envelope `json:"response"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	ep := unhex(t, v.ClientPublic)
	ch := unhex(t, v.Challenge)
	key := unhex(t, v.ContentKey)
	random := append(unhex(t, v.ServerPrivate), unhex(t, v.Nonce)...)
	out, e := rewrap(v.Payload, key, base64.RawURLEncoding.EncodeToString(ep), base64.RawURLEncoding.EncodeToString(ch), bytes.NewReader(random))
	if e != nil || out != v.Response {
		t.Fatalf("vector response mismatch: %v", e)
	}
	a, e := rewrapAAD(v.Payload, ep, ch)
	if e != nil || hex.EncodeToString(a) != v.AAD {
		t.Fatal("AAD")
	}
	salt := sha256.Sum256(a)
	if hex.EncodeToString(salt[:]) != v.Salt {
		t.Fatal("salt")
	}
	priv, e := ecdh.X25519().NewPrivateKey(unhex(t, v.ClientPrivate))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), ep) {
		t.Fatal("client public")
	}
	server, e := b64(out.E)
	if e != nil || hex.EncodeToString(server) != v.ServerPublic {
		t.Fatal("server public")
	}
	pub, _ := ecdh.X25519().NewPublicKey(server)
	shared, e := priv.ECDH(pub)
	if e != nil || hex.EncodeToString(shared) != v.Shared {
		t.Fatal("shared")
	}
	kek, _ := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/rewrap", 32)
	if hex.EncodeToString(kek) != v.KEK {
		t.Fatal("KEK")
	}
	g, _ := gcm(kek)
	ciphertext, _ := b64(out.C)
	plain, e := g.Open(nil, unhex(t, v.Nonce), ciphertext, a)
	if e != nil || !bytes.Equal(plain, key) {
		t.Fatal("client cannot unwrap", e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, a...), 0), append([]byte("other"), a[5:]...)} {
		if _, e := g.Open(nil, unhex(t, v.Nonce), ciphertext, bad); e == nil {
			t.Fatal("AAD tampering accepted")
		}
	}
}
