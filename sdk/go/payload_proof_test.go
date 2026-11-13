package sdk

import (
	"authgo/sdk/wire"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPayloadCacheAndProofVector(t *testing.T) {
	raw, e := os.ReadFile("../vectors/payload-cache-v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vector")
	}
	str := func(k string) string { var s string; json.Unmarshal(v[k], &s); return s }
	p, e := ParsePayload(v["payload"])
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := payloadB64.DecodeString(str("proof_public_key"))
	c := &Client{AppKey: p.AppKey, PublicKey: pub, CacheDir: t.TempDir(), fingerprint: str("fingerprint"), stubMode: true}
	identity := strings.Split(str("cache_identity_utf8"), "\x00")
	c.endpoint = identity[0]
	var now int64
	json.Unmarshal(v["proof_now"], &now)
	c.now = func() time.Time { return time.Unix(now, 0) }
	if c.cacheIdentity() != str("cache_identity_utf8") {
		t.Fatal("identity")
	}
	label, _ := payloadCacheLabel(p, c.fingerprint)
	if hex.EncodeToString(label) != str("label_hex") {
		t.Fatal("label")
	}
	r := &Result{ticket: str("ticket"), Source: "online"}
	path, g, aad, e := c.payloadCacheMaterial(p, r)
	if e != nil {
		t.Fatal(e)
	}
	if filepath.Base(path) != str("filename") || hex.EncodeToString(aad) != str("aad_hex") {
		t.Fatal("path/aad")
	}
	seed, _ := hex.DecodeString(str("unlock_hash_hex"))
	k := wire.ResourceKey(seed, string(label))
	if hex.EncodeToString(k) != str("cache_key_hex") {
		t.Fatal("derive")
	}
	n, _ := hex.DecodeString(str("nonce_hex"))
	dek, _ := hex.DecodeString(str("material_hex"))
	if hex.EncodeToString(g.Seal(nil, n, dek, aad)) != str("ciphertext_hex") {
		t.Fatal("cipher")
	}
	c.savePayloadProof(r)
	proof, e := os.ReadFile(c.payloadProofPath())
	if e != nil || string(proof) != str("proof_file_utf8") {
		t.Fatal("proof", e)
	}
	if filepath.Base(c.payloadProofPath()) != str("proof_filename") {
		t.Fatal("proof filename")
	}
	os.WriteFile(path, []byte(str("file_utf8")), 0600)
	got, e := c.protectedCachedKey(p)
	if e != nil || !bytes.Equal(got, dek) {
		t.Fatal("shared cache", e)
	}
	// An attacker that knows the instance ID can recompute the MAC, but not a ticket signature.
	parts := strings.Split(str("ticket"), ".")
	payload, _ := payloadB64.DecodeString(parts[0])
	altered := payloadB64.EncodeToString(bytes.Replace(payload, []byte(`"features":{}`), []byte(`"features":{"tampered":true}`), 1)) + "." + parts[1]
	forged := payloadProofPrefix + payloadB64.EncodeToString([]byte(altered)) + "." + payloadB64.EncodeToString(payloadProofMAC(c.cacheIdentity(), c.fingerprint, altered))
	os.WriteFile(c.payloadProofPath(), []byte(forged), 0600)
	if _, e = c.protectedCachedKey(p); e == nil {
		t.Fatal("forged ticket accepted")
	}
	os.WriteFile(c.payloadProofPath(), proof, 0600)
	c.fingerprint = instanceFingerprint("another-instance")
	os.WriteFile(c.payloadProofPath(), proof, 0600)
	if _, e = c.protectedCachedKey(p); e == nil {
		t.Fatal("copied instance accepted")
	}
}
func TestProtectedOnlineRefreshOutlivesLauncherAndRefusalCleans(t *testing.T) {
	s, c, p, want := payloadTLSFixture(t)
	c.stubMode = true
	ctx := context.Background()
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	if _, e := c.UnlockPayload(ctx, p); e != nil {
		t.Fatal(e)
	}
	first, _ := os.ReadFile(c.payloadProofPath())
	initialPrivate, e := os.ReadFile(c.cachePath())
	if e != nil {
		t.Fatal(e)
	}
	r, e := c.cachedResult()
	if e != nil {
		t.Fatal(e)
	}
	g, e := c.validateTicket(r.ticket, true)
	if e != nil {
		t.Fatal(e)
	}
	// Fresh program-side online proof, after the original launcher's signed grace.
	s.clock.add(g.GraceUntil.Sub(s.clock.now()) + time.Second)
	if _, e := c.Verify(ctx); e != nil {
		t.Fatal(e)
	}
	fresh, _ := os.ReadFile(c.payloadProofPath())
	if bytes.Equal(first, fresh) {
		t.Fatal("proof not refreshed")
	}
	restart := s.client(t)
	restart.CacheDir = c.CacheDir
	restart.stubMode = true
	restart.HTTPClient = unavailable()
	restart.now = s.clock.now
	// Deliberately restore the launcher's stale private cache. The shared proof
	// is newer and must be sufficient even after that old grant has expired.
	if e = os.WriteFile(c.cachePath(), initialPrivate, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = restart.guardCheck(ctx, testKey); e == nil || explicitRefusal(e) {
		t.Fatal("stale private proof control", e)
	}
	got, e := restart.protectedCachedKey(p)
	if e != nil || !bytes.Equal(got, payloadTestMaterial(want)) {
		t.Fatal("fresh shared proof failed", e)
	}
	for _, code := range []string{PayloadInvalid, NetworkError} {
		err := error(failure(code, "", nil))
		if code == PayloadInvalid {
			err = &authenticatedServerError{original: &Error{Code: code}}
		}
		c.recordPayloadResult(nil, err)
		if _, e = os.Stat(c.payloadProofPath()); e != nil {
			t.Fatal("nonrefusal cleared proof", code)
		}
	}
	s.mode = ""
	s.responseCode = LicenseRevoked
	if _, e = c.Verify(ctx); !explicitRefusal(e) {
		t.Fatal("expected authenticated refusal", e)
	}
	if _, e = os.Stat(c.payloadProofPath()); !os.IsNotExist(e) {
		t.Fatal("proof retained", e)
	}
	if len(payloadPaths(t, c)) != 0 {
		t.Fatal("key retained")
	}
}

func TestProtectedTrialAndZeroGraceDeleteSharedFiles(t *testing.T) {
	for _, kind := range []string{"trial", "zero"} {
		t.Run(kind, func(t *testing.T) {
			s, c, p, _ := payloadTLSFixture(t)
			c.stubMode = true
			if _, e := c.Check(context.Background(), testKey); e != nil {
				t.Fatal(e)
			}
			if _, e := c.UnlockPayload(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			if len(payloadPaths(t, c)) != 1 {
				t.Fatal("missing key control")
			}
			r, e := c.cachedResult()
			if e != nil {
				t.Fatal(e)
			}
			g, e := c.validateTicket(r.ticket, true)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "trial" {
				g.IsTrial = true
			} else {
				g.GraceUntil = g.IssuedAt
			}
			ticket, e := wire.EncodeTicket(g, s.private)
			if e != nil {
				t.Fatal(e)
			}
			c.recordPayloadResult(&Result{ticket: ticket, Source: "online"}, nil)
			if _, e = os.Stat(c.payloadProofPath()); !os.IsNotExist(e) || len(payloadPaths(t, c)) != 0 {
				t.Fatal("noncache authorization retained shared files", e)
			}
		})
	}
}
