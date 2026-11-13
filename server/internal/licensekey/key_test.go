package licensekey

import (
	"strings"
	"testing"
)

func TestGenerateValidateAndMutation(t *testing.T) {
	if len(Alphabet) != 32 {
		t.Fatal("alphabet must have 32 symbols")
	}
	for _, prefix := range []string{"", "AUTH", "app", "Z", strings.Repeat("A", 16)} {
		key, err := Generate(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(key); err != nil {
			t.Fatal(key, err)
		}
		if strings.ContainsAny(key, "01OI") {
			t.Fatal("ambiguous character")
		}
		for i, c := range []byte(key) {
			if c == '-' {
				continue
			}
			mutated := []byte(key)
			pos := strings.IndexByte(Alphabet, c)
			mutated[i] = Alphabet[(pos+1)%32]
			if Validate(string(mutated)) == nil {
				t.Fatalf("single substitution undetected: %s", key)
			}
		}
	}
	for _, prefix := range []string{"PREFIX", "AUTHGO", "VIP", "a-b", "0", strings.Repeat("A", 17)} {
		if _, err := Generate(prefix); err == nil {
			t.Fatal("invalid prefix", prefix)
		}
	}
	for _, bad := range []string{"", "AUTH-AAAAA-AAAAA-AAAAA", "AUTH-00000-AAAAA-AAAAA-AAAAA", "auth-AAAAA-AAAAA-AAAAA-AAAAA", strings.Repeat("X", 1000)} {
		if Validate(bad) == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
func TestTenThousandUniqueCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		key, err := Generate("BATCH")
		if err != nil {
			t.Fatal(err)
		}
		if seen[key] {
			t.Fatal("duplicate")
		}
		seen[key] = true
		if err := Validate(key); err != nil {
			t.Fatal(err)
		}
	}
}
