package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestMultiLanguageFingerprintAndCanonicalVectors(t *testing.T) {
	raw, e := os.ReadFile("../vectors/fingerprint.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases        []struct{ Machine, MAC, CPU, Expected string }
		CPUInfoCases []struct{ Name, CPUInfo, CPU, Machine, MAC, Expected string } `json:"cpuinfo_cases"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, c := range v.Cases {
		got, e := hashIdentity(c.Machine, c.MAC, c.CPU)
		if e != nil || got != c.Expected {
			t.Fatal(got, e)
		}
	}
	for _, c := range v.CPUInfoCases {
		got := parseLinuxCPU(c.CPUInfo)
		if got != c.CPU {
			t.Fatalf("%s: got %q want %q", c.Name, got, c.CPU)
		}
		hash, err := hashIdentity(c.Machine, c.MAC, got)
		if c.Expected == "" {
			if err == nil {
				t.Fatal("missing CPU accepted")
			}
		} else if err != nil || hash != c.Expected {
			t.Fatal(c.Name, hash, err)
		}
	}
	raw, e = os.ReadFile("../vectors/canonical.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Raw, Canonical string
		Invalid        []string
	}
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	got, e := canonicalizeJSON([]byte(c.Raw))
	if e != nil || string(got) != c.Canonical {
		t.Fatal(string(got), e)
	}
	for _, bad := range c.Invalid {
		if _, e := canonicalizeJSON([]byte(bad)); e == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func TestLicenseKeyVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/license-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name, Key, Code string
			Valid           bool
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			err := validateKey(c.Key)
			if (err == nil) != c.Valid {
				t.Fatal(c.Key, err)
			}
			if err != nil && !errors.Is(err, ErrInvalidLicenseKey) {
				t.Fatal(err)
			}
			if !c.Valid {
				// Invalid input must fail before endpoint, identity, network or cache access.
				client := &Client{}
				if _, err = client.Check(context.Background(), c.Key); !errors.Is(err, ErrInvalidLicenseKey) {
					t.Fatal(err)
				}
				if _, err = client.Activate(context.Background(), c.Key, ActivateOptions{}); !errors.Is(err, ErrInvalidLicenseKey) {
					t.Fatal(err)
				}
			}
		})
	}
}
