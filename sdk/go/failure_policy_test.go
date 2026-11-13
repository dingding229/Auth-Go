package sdk

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func assertProofPreserved(t *testing.T, s *signedServer, c *Client, proof []byte) {
	t.Helper()
	if c.state.Refused || c.state.Proof == nil || !bytes.Equal(c.state.Proof.Envelope, proof) {
		t.Fatal("recoverable failure changed proof or Refused")
	}
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	r, e := fresh.Verify(context.Background())
	if e != nil || r.Status != "grace" || fresh.state.Refused || fresh.state.Proof == nil {
		t.Fatal("restart lost grace", e)
	}
}
func assertOriginalWithoutProof(t *testing.T, c *Client, want error) {
	t.Helper()
	saved := c.state.Proof
	c.state.Proof = nil
	defer func() { c.state.Proof = saved }()
	r, e := c.Verify(context.Background())
	if r != nil || !errors.Is(e, want) || c.state.Refused {
		t.Fatal("original fault changed without proof", e)
	}
}
func TestGatewayTransportFailuresPreserveProof(t *testing.T) {
	for _, status := range []int{502, 503, 504, 521, 400, 500, 302, 200} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			proof := append([]byte(nil), c.state.Proof.Envelope...)
			c.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("<html>Wi-Fi login</html>"))}, nil
			})}
			r, e := c.Verify(context.Background())
			if e != nil || r.Status != "grace" || !strings.Contains(r.Reason, ResponseInvalid) {
				t.Fatal("untrusted HTTP must use grace", e)
			}
			assertProofPreserved(t, s, c, proof)
			assertOriginalWithoutProof(t, c, ErrResponseInvalid)
			c.HTTPClient = nil
			if r, e := c.Verify(context.Background()); e != nil || r.Status != "online" {
				t.Fatal(e)
			}
		})
	}
	for _, kind := range []string{"truncated", "oversized", "wrong-key", "unknown-certificate", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			proof := append([]byte(nil), c.state.Proof.Envelope...)
			c.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				switch kind {
				case "unknown-certificate":
					return nil, x509.UnknownAuthorityError{}
				case "timeout":
					return nil, &timeoutError{}
				case "truncated":
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"n":"`), &brokenReader{}))}, nil
				case "wrong-key":
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"n":"AAAAAAAAAAAAAAAA","c":"AAAAAAAAAAAAAAAAAAAAAA"}`))}, nil
				default:
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponse+1)))}, nil
				}
			})}
			r, e := c.Verify(context.Background())
			if e != nil || r.Status != "grace" || r.Reason == "" {
				t.Fatal("must use grace", e)
			}
			assertProofPreserved(t, s, c, proof)
			want := error(ErrResponseInvalid)
			if kind == "timeout" {
				want = ErrNetworkError
			}
			assertOriginalWithoutProof(t, c, want)
			c.HTTPClient = nil
			if r, e := c.Verify(context.Background()); e != nil || r.Status != "online" {
				t.Fatal(e)
			}
		})
	}
}

type brokenReader struct{}

func (*brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type timeoutError struct{}

func (*timeoutError) Error() string   { return "simulated timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

func TestAuthenticatedTemporaryErrorsAndRefusals(t *testing.T) {
	for _, code := range []string{InternalError, RateLimited, ReplayDetected, TimestampInvalid, SignatureInvalid, InvalidRequest, LicenseRevoked, LicenseSuspended, UserDisabled, "UNKNOWN_AUTHENTICATED_ERROR", ResponseSignatureInvalid} {
		t.Run(code, func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			proof := append([]byte(nil), c.state.Proof.Envelope...)
			s.mu.Lock()
			s.responseCode = code
			s.mu.Unlock()
			r, e := c.Verify(context.Background())
			if temporaryServerCode(code) {
				if e != nil || r.Status != "grace" || !strings.Contains(r.Reason, code) {
					t.Fatal("temporary error did not use grace", e)
				}
				assertProofPreserved(t, s, c, proof)
				assertOriginalWithoutProof(t, c, &Error{Code: code})
				s.mu.Lock()
				s.responseCode = ""
				s.mu.Unlock()
				if r, e := c.Verify(context.Background()); e != nil || r.Status != "online" {
					t.Fatal(e)
				}
			} else {
				if r != nil || !errors.Is(e, &Error{Code: code}) || !c.state.Refused || c.state.Proof != nil {
					t.Fatal("authenticated refusal not enforced", e)
				}
				fresh := s.client(t)
				fresh.CacheDir = c.CacheDir
				fresh.HTTPClient = unavailable()
				if r, e := fresh.Verify(context.Background()); r != nil || e == nil || !fresh.state.Refused {
					t.Fatal("refusal cache restored", e)
				}
			}
		})
	}
}
func TestOriginalErrorsWithoutProofAndExpiredGraceCause(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	c.state.Proof = nil
	c.persist()
	s.set("bad-signature")
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrResponseSignatureInvalid) || c.state.Refused {
		t.Fatal("original error lost", e)
	}
	s.set("")
	activate(t, c)
	c.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return nil, x509.UnknownAuthorityError{} })}
	c.state.Proof = nil
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrResponseInvalid) {
		t.Fatal(e)
	} else {
		var cert x509.UnknownAuthorityError
		if !errors.As(e, &cert) {
			t.Fatal("certificate cause lost")
		}
	}
	c.HTTPClient = nil
	activate(t, c)
	s.set("503")
	s.clock.add(2 * time.Hour)
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrGraceExpired) || !errors.Is(e, ErrInternalError) {
		t.Fatal("expired grace lost original cause", e)
	}
}
func TestClassificationVectors(t *testing.T) {
	raw, e := os.ReadFile("../vectors/error-classification.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Authenticated bool   `json:"authenticated"`
			Code          string `json:"code"`
			Class         string `json:"class"`
			Clear         bool   `json:"clear_cache"`
		} `json:"cases"`
	}
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, tc := range v.Cases {
		var err error = &Error{Code: tc.Code}
		if tc.Authenticated {
			err = &authenticatedServerError{original: &Error{Code: tc.Code}}
		}
		if explicitRefusal(err) != tc.Clear {
			t.Fatal("classification vector mismatch", tc.Code)
		}
		if tc.Authenticated && tc.Class == "temporary" && !temporaryServerCode(tc.Code) {
			t.Fatal(tc.Code)
		}
	}
}
func TestAutoCheckUsesRecoverablePolicy(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	s.set("bad-signature")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.wait = func(_ context.Context, d time.Duration) error { s.clock.add(d); s.set(""); return nil }
	n := 0
	e := c.StartAutoCheck(ctx, func(r *Result, e error) {
		if e != nil {
			t.Fatal(e)
		}
		n++
		if n == 1 && r.Status != "grace" {
			t.Fatal("auto bypassed fallback")
		}
		if n == 2 {
			if r.Status != "online" {
				t.Fatal("auto failed recovery")
			}
			cancel()
		}
	})
	if !errors.Is(e, context.Canceled) || n != 2 {
		t.Fatal(e, n)
	}
}
func TestActivateAndDeactivateDoNotConvertFailuresIntoRefusals(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	s.set("bad-signature")
	if r, e := c.Activate(context.Background(), testKey, ActivateOptions{}); r != nil || !errors.Is(e, ErrResponseSignatureInvalid) || c.state.Refused {
		t.Fatal("fresh activation failed classification", e)
	}
	s.set("")
	activate(t, c)
	proof := append([]byte(nil), c.state.Proof.Envelope...)
	s.set("bad-signature")
	if r, e := c.Activate(context.Background(), testKey, ActivateOptions{ClientVersion: "1.2.3"}); r != nil || e == nil {
		t.Fatal("Activate must fail rather than return cached success")
	}
	assertProofPreserved(t, s, c, proof)
	if e := c.Deactivate(context.Background()); !errors.Is(e, ErrResponseSignatureInvalid) {
		t.Fatal(e)
	}
	assertProofPreserved(t, s, c, proof)
	s.set("")
	if e := c.Deactivate(context.Background()); e != nil || c.state.Proof != nil || !c.state.Refused {
		t.Fatal("successful unbind did not clear", e)
	}
}
func TestUntrustedTemporaryFaultCannotExtendGraceOrBecomeOnline(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	s.clock.add(2 * time.Hour)
	s.set("unsigned")
	r, e := c.Verify(context.Background())
	if r != nil || !errors.Is(e, ErrGraceExpired) || c.state.Refused || c.state.Proof == nil {
		t.Fatal("expired grace must stop without trusting fault", e)
	}
	s.set("")
	if r, e := c.Verify(context.Background()); e != nil || r.Status != "online" {
		t.Fatal(e)
	}
}

func TestRefusalCodeWithoutFullAuthenticationCannotClear(t *testing.T) {
	for _, mode := range []string{"bad-signature", "unsigned", "wrong-nonce", "future-ts", "wrong-encryption-key"} {
		t.Run(mode, func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			proof := append([]byte(nil), c.state.Proof.Envelope...)
			s.mu.Lock()
			s.responseCode = LicenseRevoked
			s.mode = mode
			s.mu.Unlock()
			if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" {
				t.Fatal("untrusted refusal code became authoritative", e)
			}
			assertProofPreserved(t, s, c, proof)
		})
	}
}
