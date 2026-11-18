package sdk

import (
	"authgo/sdk/wire"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestVersionsResponseVerificationVector(t *testing.T) {
	raw, err := os.ReadFile("../vectors/versions-response.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Op        string          `json:"op"`
		PublicKey string          `json:"public_key"`
		Canonical string          `json:"canonical_signed"`
		Response  json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil || vector.Op != "versions" {
		t.Fatal("invalid versions vector", err)
	}
	public, err := base64.StdEncoding.Strict().DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var signed envelope
	if err := json.Unmarshal(vector.Response, &signed); err != nil {
		t.Fatal(err)
	}
	canonical, err := wire.CanonicalJSON(map[string]any{"code": signed.Code, "data": signed.Data, "ts": signed.TS})
	if err != nil || string(canonical) != vector.Canonical {
		t.Fatal("versions vector canonical bytes changed", err)
	}
	c := &Client{PublicKey: public, now: func() time.Time { return time.Unix(signed.TS, 0) }}
	_, data, err := c.authenticateEnvelope(vector.Response, signed.Nonce, vector.Op, true, 200)
	if err != nil {
		t.Fatal(err)
	}
	items, next, err := decodeVersions(data, 2)
	if err != nil || len(items) != 2 || next == "" || items[0].Version != "1.2.0" || items[0].Changelog != "示例 <notes>\n第二行" || !items[0].Mandatory || items[0].Entitled || items[0].PublishedAt.Format(time.RFC3339) != "2026-11-18T00:00:00Z" || items[1].Changelog != "" || items[1].Mandatory || !items[1].Entitled {
		t.Fatal("versions vector business data did not survive verification", err)
	}
}

func TestVersionsGatewayAndOptions(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	proof := append([]byte(nil), c.state.Proof.Envelope...)
	cache, err := os.ReadFile(c.cachePath())
	if err != nil {
		t.Fatal(err)
	}
	s.versionsResponse = func(raw json.RawMessage, data map[string]any) {
		var in struct {
			Limit     int    `json:"limit"`
			Before    string `json:"before"`
			Token     string `json:"activation_token"`
			Challenge string `json:"challenge"`
		}
		if json.Unmarshal(raw, &in) != nil || in.Limit != 2 || in.Before != "next-page" || in.Token == "" || in.Challenge == "" {
			t.Error("versions request missing expected fields")
		}
		data["items"] = []map[string]any{{"version": "1.2.0", "changelog": "notes", "published_at": time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), "mandatory": true, "entitled": false}}
		data["next_cursor"] = "cursor-2"
	}
	items, next, err := c.Versions(context.Background(), VersionsOptions{Limit: 2, Before: "next-page"})
	if err != nil || len(items) != 1 || items[0].Version != "1.2.0" || !items[0].Mandatory || items[0].Entitled || items[0].PublishedAt == nil || next != "cursor-2" {
		t.Fatal("invalid versions response", err)
	}
	after, err := os.ReadFile(c.cachePath())
	if err != nil || !bytes.Equal(cache, after) {
		t.Fatal("versions mutated cache", err)
	}
	assertProofPreserved(t, s, c, proof)
	if _, _, err = c.Versions(context.Background(), VersionsOptions{Limit: 201}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("invalid limit accepted")
	}
}

func TestVersionsRequiresActivationAndVerifiesResponse(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	if _, _, err := c.Versions(context.Background(), VersionsOptions{}); !errors.Is(err, ErrNotActivated) {
		t.Fatal("missing activation was accepted", err)
	}
	activate(t, c)
	for _, mode := range []string{"bad-signature", "wrong-nonce", "old-ts"} {
		s.mu.Lock()
		s.mode = mode
		s.versionsResponse = func(_ json.RawMessage, data map[string]any) { data["items"] = []any{}; data["next_cursor"] = "" }
		s.mu.Unlock()
		if _, _, err := c.Versions(context.Background(), VersionsOptions{}); err == nil {
			t.Fatal("untrusted response accepted", mode)
		}
	}
	s.mu.Lock()
	s.mode = ""
	s.responseCode = LicenseRevoked
	s.mu.Unlock()
	cached, err := os.ReadFile(c.cachePath())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Versions(context.Background(), VersionsOptions{}); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatal("authenticated refusal lost", err)
	}
	cachedAfter, err := os.ReadFile(c.cachePath())
	if err != nil || !bytes.Equal(cached, cachedAfter) || c.state.Refused {
		t.Fatal("informational refusal mutated licensing state", err)
	}
	s.mu.Lock()
	s.responseCode = ""
	s.versionsResponse = func(_ json.RawMessage, data map[string]any) {
		data["items"] = []map[string]any{{"version": "1.0.0"}}
		data["next_cursor"] = ""
	}
	s.mu.Unlock()
	if _, _, err := c.Versions(context.Background(), VersionsOptions{}); !errors.Is(err, ErrResponseInvalid) {
		t.Fatal("incomplete response accepted", err)
	}
}

func TestVersionsEmptyAndNullCursor(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	s.mu.Lock()
	s.versionsResponse = func(_ json.RawMessage, data map[string]any) { data["items"] = []any{}; data["next_cursor"] = "" }
	s.mu.Unlock()
	items, next, err := c.Versions(context.Background(), VersionsOptions{})
	if err != nil || items == nil || len(items) != 0 || next != "" {
		t.Fatal("empty page invalid", err)
	}
	s.mu.Lock()
	s.versionsResponse = func(_ json.RawMessage, data map[string]any) { data["items"] = []any{}; data["next_cursor"] = nil }
	s.mu.Unlock()
	if _, _, err := c.Versions(context.Background(), VersionsOptions{}); !errors.Is(err, ErrResponseInvalid) {
		t.Fatal("null cursor accepted", err)
	}
}
