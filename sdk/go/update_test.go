package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestUpdateResponseVerificationVector(t *testing.T) {
	raw, e := os.ReadFile("../vectors/update-response.json")
	if e != nil {
		t.Fatal(e)
	}
	type vector struct {
		Public    string          `json:"public_key"`
		Canonical string          `json:"canonical_signed"`
		Signature string          `json:"signature"`
		Response  json.RawMessage `json:"response"`
	}
	var root struct {
		vector
		Manual []vector `json:"docker_cases"`
	}
	if e = json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	if len(root.Manual) != 2 {
		t.Fatal("Docker Hub vectors missing")
	}
	all := append([]vector{root.vector}, root.Manual...)
	for _, v := range all {
		public, _ := base64.StdEncoding.DecodeString(v.Public)
		sig, _ := base64.StdEncoding.DecodeString(v.Signature)
		var env envelope
		if e := json.Unmarshal(v.Response, &env); e != nil {
			t.Fatal(e)
		}
		canonical, e := canonicalJSON(map[string]any{"code": env.Code, "data": env.Data, "ts": env.TS})
		if e != nil || string(canonical) != v.Canonical || !ed25519.Verify(public, canonical, sig) {
			t.Fatal("update vector mismatch", e)
		}
		var update Update
		data, _ := json.Marshal(env.Data)
		if e := json.Unmarshal(data, &update); e != nil {
			t.Fatal(e)
		}
		if !update.Available {
			t.Fatal("Docker Hub update availability", update)
		}
	}
}

// Update failures, including authenticated license refusals, are informational:
// only authorization actions may revoke the locally cached licensing proof.
func TestUpdateFailuresNeverMutateLicenseCache(t *testing.T) {
	var vectors struct {
		UpdateCases []struct {
			Op    string `json:"op"`
			Code  string `json:"code"`
			Clear bool   `json:"clear_cache"`
		} `json:"update_cases"`
	}
	raw, err := os.ReadFile("../vectors/error-classification.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &vectors); err != nil || len(vectors.UpdateCases) < 8 {
		t.Fatal("missing update vectors", err)
	}
	for _, tc := range vectors.UpdateCases {
		t.Run("update.check/"+tc.Code, func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			proof := append([]byte(nil), c.state.Proof.Envelope...)
			cache, err := os.ReadFile(c.cachePath())
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.responseCode = tc.Code
			s.mu.Unlock()
			_, err = c.CheckUpdate(context.Background(), "1.0.0")
			if !errors.Is(err, &Error{Code: tc.Code}) || tc.Clear {
				t.Fatal("original update error lost", err)
			}
			after, err := os.ReadFile(c.cachePath())
			if err != nil || !bytes.Equal(cache, after) {
				t.Fatal("update wrote cache", err)
			}
			assertProofPreserved(t, s, c, proof)
		})
	}
}
