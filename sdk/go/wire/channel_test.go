package wire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestHKDFRFC5869(t *testing.T) {
	out := HKDF(bytes.Repeat([]byte{0x0b}, 22), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}, 42)
	if hex.EncodeToString(out) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatal("RFC5869 mismatch")
	}
}
func TestPaddingAndChannelIntegrity(t *testing.T) {
	for _, n := range []int{1, 507, 508, 509, 1020, 1021} {
		raw := bytes.Repeat([]byte{'a'}, n)
		p, e := Pad(raw)
		if e != nil || len(p)%512 != 0 || len(p) != max(4096, ((n+4+511)/512)*512) {
			t.Fatal(n, e)
		}
		out, e := Unpad(p)
		if e != nil || !bytes.Equal(out, raw) {
			t.Fatal(n, e)
		}
	}
	for _, p := range [][]byte{nil, make([]byte, 1), make([]byte, 512), bytes.Repeat([]byte{255}, 512)} {
		if _, e := Unpad(p); e == nil {
			t.Fatal("accepted invalid padding")
		}
	}
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	r, client, e := Encrypt(priv.PublicKey().Bytes(), []byte(`{"op":"verify"}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, server, e := Decrypt(priv, r)
	if e != nil || string(raw) != `{"op":"verify"}` {
		t.Fatal(e)
	}
	response, e := server.EncryptResponse([]byte(`{"code":"OK"}`))
	if e != nil {
		t.Fatal(e)
	}
	out, e := client.DecryptResponse(response)
	if e != nil || string(out) != `{"code":"OK"}` {
		t.Fatal(e)
	}
	_, other, _ := Encrypt(priv.PublicKey().Bytes(), []byte(`{}`))
	if _, e := other.DecryptResponse(response); e == nil {
		t.Fatal("cross-request response accepted")
	}
	for _, field := range []string{"k", "e", "n", "c"} {
		bad := r
		switch field {
		case "k":
			bad.K = "bad"
		case "e":
			bad.E = B64.EncodeToString(make([]byte, 32))
		case "n":
			n, _ := B64.DecodeString(bad.N)
			n[0] ^= 1
			bad.N = B64.EncodeToString(n)
		case "c":
			c, _ := B64.DecodeString(bad.C)
			c[len(c)-1] ^= 1
			bad.C = B64.EncodeToString(c)
		}
		if _, _, e := Decrypt(priv, bad); e == nil {
			t.Fatal("tamper accepted", field)
		}
	}
}
func TestCrossLanguageVectors(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		GatewayPrivate string   `json:"gateway_private_hex"`
		Ephemeral      string   `json:"ephemeral_private_hex"`
		Inner          string   `json:"inner"`
		Padding        string   `json:"padding_hex"`
		Request        Request  `json:"request"`
		ReqKey         string   `json:"request_key_hex"`
		ResKey         string   `json:"response_key_hex"`
		ReqAAD         string   `json:"request_aad_hex"`
		ResAAD         string   `json:"response_aad_hex"`
		Public         string   `json:"ed25519_public"`
		Ticket         string   `json:"ticket"`
		Response       Response `json:"response"`
		ResponsePlain  string   `json:"response_plain"`
		UnlockSeed     string   `json:"unlock_seed_hex"`
		UnlockLabel    string   `json:"unlock_label"`
		UnlockKey      string   `json:"unlock_key_hex"`
		Resource       string   `json:"resource"`
	}
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	decodeHex := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	priv, _ := ecdh.X25519().NewPrivateKey(decodeHex(v.GatewayPrivate))
	ep, _ := ecdh.X25519().NewPrivateKey(decodeHex(v.Ephemeral))
	r, s, e := EncryptWith(ep, priv.PublicKey().Bytes(), []byte(v.Inner), bytes.NewReader(make([]byte, 8192)))
	if e != nil || r != v.Request || hex.EncodeToString(s.RequestKey) != v.ReqKey || hex.EncodeToString(s.ResponseKey) != v.ResKey || hex.EncodeToString(s.AAD) != v.ReqAAD || hex.EncodeToString(s.ResponseAAD) != v.ResAAD {
		t.Fatal("channel vector mismatch", e)
	}
	pad, _ := PadWith([]byte(v.Inner), bytes.NewReader(make([]byte, 8192)))
	if hex.EncodeToString(pad) != v.Padding {
		t.Fatal("padding vector mismatch")
	}
	out, e := s.DecryptResponse(v.Response)
	if e != nil || string(out) != v.ResponsePlain {
		t.Fatal("response vector mismatch", e)
	}
	if hex.EncodeToString(ResourceKey(decodeHex(v.UnlockSeed), v.UnlockLabel)) != v.UnlockKey {
		t.Fatal("unlock vector mismatch")
	}
	parts := strings.Split(v.Resource, ".")
	if len(parts) != 3 {
		t.Fatal("resource vector")
	}
	nonce, _ := B64.DecodeString(parts[1])
	ct, _ := B64.DecodeString(parts[2])
	plaintext, e := Open(ResourceKey(decodeHex(v.UnlockSeed), v.UnlockLabel), nonce, ct, []byte("authgo-resource-v2\x00"+v.UnlockLabel))
	if e != nil || string(plaintext) != "hello" {
		t.Fatal("resource vector mismatch", e)
	}
	var in Inner
	json.Unmarshal([]byte(v.Inner), &in)
	if MAC([]byte("test-secret-only"), in.Op, in.Timestamp, in.Nonce, in.Body) != in.Signature {
		t.Fatal("HMAC vector mismatch")
	}
	public, _ := B64.DecodeString(v.Public)
	if _, e := DecodeTicket(v.Ticket, ed25519.PublicKey(public)); e != nil {
		t.Fatal(e)
	}
	parts = strings.Split(v.Ticket, ".")
	payload, _ := B64.DecodeString(parts[0])
	if !Verify(TicketDomain, payload, parts[1], public) || Verify("invalid-domain\x00", payload, parts[1], public) {
		t.Fatal("ticket signature domain separation")
	}
}

func TestHKDFJSONVector(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/hkdf.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		IKM    string `json:"ikm_hex"`
		Salt   string `json:"salt_hex"`
		Info   string `json:"info_hex"`
		Length int    `json:"length"`
		OKM    string `json:"okm_hex"`
	}
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	ikm, e := hex.DecodeString(v.IKM)
	if e != nil {
		t.Fatal(e)
	}
	salt, _ := hex.DecodeString(v.Salt)
	info, _ := hex.DecodeString(v.Info)
	if hex.EncodeToString(HKDF(ikm, salt, info, v.Length)) != v.OKM {
		t.Fatal("HKDF JSON vector mismatch")
	}
}
