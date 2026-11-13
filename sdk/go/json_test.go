package sdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonicalJSON(t *testing.T) {
	raw := []byte(` { "z": [ {"b":2,"a":1}, true, null ], "a": {"汉":18446744073709551615,"b":1.00} } `)
	got, err := canonicalizeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"b":1.00,"汉":18446744073709551615},"z":[{"a":1,"b":2},true,null]}`
	if string(got) != want {
		t.Fatalf("canonical: %s", got)
	}
	again, err := canonicalizeJSON(got)
	if err != nil || string(again) != want {
		t.Fatal("not idempotent")
	}
	value := map[string]any{"z": []any{map[string]any{"b": 2, "a": 1}, true, nil}, "a": map[string]any{"汉": uint64(math.MaxUint64), "b": json.Number("1.00")}}
	goJSON, err := canonicalJSON(value)
	if err != nil || string(goJSON) != want {
		t.Fatalf("Go canonical: %s %v", goJSON, err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	signature := ed25519.Sign(private, got)
	if !ed25519.Verify(public, again, signature) {
		t.Fatal("canonical signature mismatch")
	}
	for _, raw := range []string{`{"b":1,"a":2}`, `{"a":2,"b":1}`} {
		canonical, _ := canonicalizeJSON([]byte(raw))
		if string(canonical) != `{"a":2,"b":1}` {
			t.Fatal("key order not stable")
		}
	}
}
func TestCanonicalJSONRejectsAmbiguity(t *testing.T) {
	for _, raw := range []string{"", `{"a":1,"a":2}`, `{"nested":{"a":1,"\u0061":2}}`, `{} {}`, `[1,]`, `{}`, `{"a":`, string([]byte{'"', 0xff, '"'}), strings.Repeat("[", 102) + "0" + strings.Repeat("]", 102)} {
		_, err := canonicalizeJSON([]byte(raw))
		if raw == `{}` {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("invalid canonical input accepted: %q", raw)
		}
	}
	for _, value := range []any{math.NaN(), math.Inf(1), make(chan int), json.RawMessage(`{"a":`)} {
		if _, err := canonicalJSON(value); err == nil {
			t.Fatal("invalid Go JSON accepted")
		}
	}
}

func TestCanonicalUnicodeEscapes(t *testing.T) {
	for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800\u0041"`, `"\u123"`} {
		if _, err := canonicalizeJSON([]byte(raw)); err == nil {
			t.Fatalf("invalid Unicode accepted: %s", raw)
		}
	}
	for _, raw := range []string{`"\ud83d\ude00"`, `"😀"`, `"\\ud800"`, `"\u4e2d"`} {
		if _, err := canonicalizeJSON([]byte(raw)); err != nil {
			t.Fatalf("valid Unicode rejected: %s %v", raw, err)
		}
	}
}
