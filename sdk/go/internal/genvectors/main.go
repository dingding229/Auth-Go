package main

import (
	"authgo/sdk/wire"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"
)

func main() {
	priv, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	ep, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	body, _ := json.Marshal(map[string]string{"license_key": "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM", "device_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "activation_token": "act_" + wire.B64.EncodeToString(bytes.Repeat([]byte{3}, 32)), "challenge": wire.B64.EncodeToString(bytes.Repeat([]byte{4}, 32)), "hostname": "test-pc", "os": "linux/amd64", "client_version": "1.0.0"})
	inner := wire.Inner{AppKey: "app_test", Op: "verify", Timestamp: "1793692800", Nonce: "test-nonce-0123456789", Body: body}
	inner.Signature = wire.MAC([]byte("test-secret-only"), inner.Op, inner.Timestamp, inner.Nonce, body)
	raw, _ := json.Marshal(inner)
	r, s, _ := wire.EncryptWith(ep, priv.PublicKey().Bytes(), raw, bytes.NewReader(make([]byte, 8192)))
	pad, _ := wire.PadWith(raw, bytes.NewReader(make([]byte, 8192)))
	ed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	now := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	g := wire.Grant{V: 2, AppKey: "app_test", Challenge: wire.B64.EncodeToString(bytes.Repeat([]byte{4}, 32)), LicenseID: 7, LicenseRef: wire.Hash([]byte("test-ref")), DeviceHash: wire.Hash([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")), Status: "active", IssuedAt: now, Features: json.RawMessage(`{"export":true}`), NextCheckIn: 3600, GraceUntil: now.Add(72 * time.Hour), UnlockHash: wire.Hash(bytes.Repeat([]byte{5}, 32))}
	grant, _ := json.Marshal(g)
	ticket := wire.B64.EncodeToString(grant) + "." + wire.Sign(wire.TicketDomain, grant, ed)
	resource := wire.ResourceKey(bytes.Repeat([]byte{5}, 32), "settings")
	ct, _ := wire.Seal(resource, make([]byte, 12), []byte("hello"), []byte("authgo-resource-v2\x00settings"))
	responsePlain := []byte(`{"code":"OK"}`)
	responsePad, _ := wire.PadWith(responsePlain, bytes.NewReader(make([]byte, 8192)))
	responseCT, _ := wire.Seal(s.ResponseKey, bytes.Repeat([]byte{6}, 12), responsePad, s.ResponseAAD)
	v := map[string]any{"response_plain": string(responsePlain), "response": wire.Response{N: wire.B64.EncodeToString(bytes.Repeat([]byte{6}, 12)), C: wire.B64.EncodeToString(responseCT)}, "warning": "TEST KEYS ONLY / 零随机数仅用于固定测试向量，生产必须使用CSPRNG", "gateway_private_hex": hex.EncodeToString(priv.Bytes()), "gateway_public": wire.B64.EncodeToString(priv.PublicKey().Bytes()), "ephemeral_private_hex": hex.EncodeToString(ep.Bytes()), "inner": string(raw), "padding_hex": hex.EncodeToString(pad), "request": r, "request_key_hex": hex.EncodeToString(s.RequestKey), "response_key_hex": hex.EncodeToString(s.ResponseKey), "request_aad_hex": hex.EncodeToString(s.AAD), "response_aad_hex": hex.EncodeToString(s.ResponseAAD), "ed25519_seed_hex": hex.EncodeToString(ed.Seed()), "ed25519_public": wire.B64.EncodeToString(ed.Public().(ed25519.PublicKey)), "ticket": ticket, "unlock_seed_hex": hex.EncodeToString(bytes.Repeat([]byte{5}, 32)), "unlock_label": "settings", "unlock_key_hex": hex.EncodeToString(resource), "resource": "AUTHGO-DATA-v2." + wire.B64.EncodeToString(make([]byte, 12)) + "." + wire.B64.EncodeToString(ct)}
	out, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile("../vectors/v2.json", append(out, '\n'), 0644)
}
