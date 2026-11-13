package integration

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	in := Config{URL: "https://auth.example.com/", AppKey: "app_test", AppSecret: "private-secret", PublicKey: "public"}
	v, e := Encode(in)
	if e != nil {
		t.Fatal(e)
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, "authgo2."))
	if e != nil {
		t.Fatal(e)
	}
	var out Config
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if out.AppSecret != in.AppSecret || out.URL != "https://auth.example.com" {
		t.Fatal("round trip failed")
	}
	for _, v := range []string{"", "https://private-secret@example.com", "http://example.com/?x=private-secret", "http://example.com/path"} {
		if _, e = NormalizeURL(v); e == nil || strings.Contains(e.Error(), "private-secret") {
			t.Fatalf("unsafe error: %v", e)
		}
	}
}
