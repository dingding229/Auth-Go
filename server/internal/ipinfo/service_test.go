package ipinfo

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	s, e := New(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", name+".mmdb"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func upload(t *testing.T, s *Service, kind, name string) {
	t.Helper()
	if e := s.Upload(context.Background(), kind, bytes.NewReader(fixture(t, name))); e != nil {
		t.Fatal(e)
	}
}
func TestLocalLookupAndPersistence(t *testing.T) {
	s := testService(t)
	if s.Lookup("8.8.8.8") != nil {
		t.Fatal("default must omit info")
	}
	upload(t, s, "city", "city")
	dirInfo, statErr := os.Stat(s.dir)
	if statErr != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("directory permissions: %v %v", dirInfo, statErr)
	}
	fileInfo, statErr := os.Stat(filepath.Join(s.dir, s.snapshot().City.File))
	if statErr != nil || fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("file permissions: %v %v", fileInfo, statErr)
	}
	if got := s.Lookup("8.8.8.8"); got.City != "上海" || got.ASN != 0 || got.CountryCode != "CN" || got.Country != "中国" {
		t.Fatalf("city: %+v", got)
	}
	upload(t, s, "asn", "asn")
	for _, ip := range []string{"8.8.8.8", "2001:4860::8888", "::ffff:8.8.8.8"} {
		got := s.Lookup(ip)
		if got.City != "上海" || got.Region != "上海" || got.ASN != 64500 || got.ASOrg != "Synthetic Network" || got.Scope != "public" {
			t.Fatalf("%s: %+v", ip, got)
		}
	}
	for ip, want := range map[string]string{"10.0.0.1": "private", "fc00::1": "private", "169.254.1.2": "private", "127.0.0.1": "loopback", "::1": "loopback", "garbage": "unknown", "0.0.0.0": "unknown", "203.0.113.1": "unknown"} {
		if got := s.Lookup(ip); got.Scope != want || got.City != "" || got.ASN != 0 {
			t.Fatalf("%s: %+v", ip, got)
		}
	}
	if got := s.Lookup("9.9.9.9"); got.Scope != "public" || got.City != "" || got.ASN != 0 {
		t.Fatal(got)
	}
	out := s.LookupBatch([]string{"8.8.8.8", "8.8.8.8"})
	if len(out) != 1 {
		t.Fatal("not deduped")
	}
	// Return copies: a caller cannot mutate the cached record.
	out["8.8.8.8"].City = "changed"
	if s.Lookup("8.8.8.8").City != "上海" {
		t.Fatal("cache alias")
	}
	again, e := New(filepath.Dir(s.dir))
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if got := again.Lookup("8.8.8.8"); got.ASN != 64500 || got.City != "上海" {
		t.Fatal(got)
	}
	if e = s.Delete(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s.Lookup("8.8.8.8") != nil || s.Status().City != nil {
		t.Fatal("delete did not disable")
	}
	entries, e := os.ReadDir(s.dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("delete leftovers: %v %v", entries, e)
	}
}
func TestOnlyASNAndMaxMindTraits(t *testing.T) {
	s := testService(t)
	upload(t, s, "asn", "asn-traits")
	if got := s.Lookup("8.8.8.8"); got.ASN != 64500 || got.Country != "" {
		t.Fatal(got)
	}
}
func TestInvalidAndCanceledUploadPreserveOld(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	before := s.snapshot().City.File
	for _, b := range [][]byte{[]byte("invalid"), fixture(t, "asn"), fixture(t, "city")[:100]} {
		if e := s.Upload(context.Background(), "city", bytes.NewReader(b)); e == nil {
			t.Fatal("accepted invalid/wrong-kind file")
		}
		if s.Lookup("8.8.8.8").City != "上海" || s.snapshot().City.File != before {
			t.Fatal("old lost")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.Upload(ctx, "city", bytes.NewReader(fixture(t, "city-other"))); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if s.Lookup("8.8.8.8").City != "上海" {
		t.Fatal("canceled replaced")
	}
	if e := s.Upload(context.Background(), "../../evil", bytes.NewReader(nil)); e == nil {
		t.Fatal("invalid kind")
	}
}
func TestConcurrentAtomicReplacementAndBoundedCache(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	old := s.snapshot().City.File
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 1000; j++ {
				got := s.Lookup("8.8.8.8")
				if got == nil || got.CountryCode != "CN" && got.CountryCode != "US" {
					t.Errorf("torn lookup: %+v", got)
					return
				}
			}
		})
	}
	for i := 0; i < 12; i++ {
		name := "city"
		if i%2 == 0 {
			name = "city-other"
		}
		upload(t, s, "city", name)
	}
	wg.Wait()
	if _, e := os.Stat(filepath.Join(s.dir, old)); !os.IsNotExist(e) {
		t.Fatal("old file left behind")
	}
	for i := 0; i < cacheCapacity+200; i++ {
		s.Lookup(time.Unix(int64(i), 0).String())
	}
	if len(s.cache) > cacheCapacity {
		t.Fatal("unbounded cache")
	}
	upload(t, s, "city", "city-other")
	if s.Lookup("8.8.8.8").CountryCode != "US" {
		t.Fatal("stale cache")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func compressed(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(b)
	_ = w.Close()
	return out.Bytes()
}
func TestDownloadSafetyAndPreservation(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	cases := []struct {
		name   string
		body   []byte
		length int64
		status int
	}{
		{"corrupt gzip", []byte("bad"), 3, 200},
		{"corrupt mmdb", compressed([]byte("not mmdb")), -1, 200},
		{"oversize compressed", nil, MaxCompressedBytes + 1, 200},
		{"http failure", nil, 0, 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.download = func(ctx context.Context, kind string, month time.Time) (*prepared, error) {
				return s.fetch(ctx, &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tc.status, ContentLength: tc.length, Body: io.NopCloser(bytes.NewReader(tc.body))}, nil
				})}, downloadURL(kind, month), kind)
			}
			if e := s.Enable(context.Background()); e == nil {
				t.Fatal("accepted bad download")
			}
			if s.Lookup("8.8.8.8").City != "上海" {
				t.Fatal("old lost")
			}
		})
	}
}
func TestDecompressionBombAndUploadSize(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	chunk := make([]byte, 1<<20)
	for n := int64(0); n <= MaxDatabaseBytes; n += int64(len(chunk)) {
		_, _ = w.Write(chunk)
	}
	_ = w.Close()
	_, e := s.fetch(context.Background(), &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: int64(b.Len()), Body: io.NopCloser(bytes.NewReader(b.Bytes()))}, nil
	})}, downloadURL("city", time.Now()), "city")
	if e == nil || !strings.Contains(e.Error(), "512 MiB") {
		t.Fatal(e)
	}
	if e = s.Upload(context.Background(), "city", io.LimitReader(zeroReader{}, MaxDatabaseBytes+1)); e == nil {
		t.Fatal("unbounded upload")
	}
	if s.Lookup("8.8.8.8").City != "上海" {
		t.Fatal("bomb replaced old")
	}
	files, _ := os.ReadDir(s.dir)
	if len(files) != 2 {
		t.Fatalf("temp files left: %v", files)
	}
	c := &compressedReader{r: io.LimitReader(zeroReader{}, MaxCompressedBytes+1)}
	if _, e = io.Copy(io.Discard, c); e == nil {
		t.Fatal("unbounded compressed body")
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
func TestRedirectAndURLPolicy(t *testing.T) {
	base, _ := http.NewRequest("GET", "https://download.db-ip.com/free/a", nil)
	for _, raw := range []string{"http://download.db-ip.com/free/b", "https://evil.example/free/b", "https://download.db-ip.com:444/free/b", "https://user@download.db-ip.com/free/b"} {
		r, _ := http.NewRequest("GET", raw, nil)
		if redirect(r, []*http.Request{base}) == nil {
			t.Fatal(raw)
		}
	}
	next, _ := http.NewRequest("GET", "https://download.db-ip.com/free/b", nil)
	if e := redirect(next, []*http.Request{base}); e != nil {
		t.Fatal(e)
	}
	s := testService(t)
	for _, raw := range []string{"http://download.db-ip.com/free/a", "https://evil.example/a"} {
		if _, e := s.fetch(context.Background(), nil, raw, "city"); e == nil {
			t.Fatal(raw)
		}
	}
	client := downloadClient()
	defer client.CloseIdleConnections()
	dial := client.Transport.(*http.Transport).DialContext
	for _, addr := range []string{"127.0.0.1:443", "download.db-ip.com:80", "evil.example:443"} {
		if _, e := dial(context.Background(), "tcp", addr); e == nil {
			t.Fatal(addr)
		}
	}
	// Exercise net/http redirect handling, not just the callback.
	client = &http.Client{CheckRedirect: redirect, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://evil.example/b"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	if _, e := s.fetch(context.Background(), client, base.URL.String(), "city"); e == nil {
		t.Fatal("redirect followed")
	}
}
func TestMonthlyFallbackPairRollbackAndUploadedPreservation(t *testing.T) {
	s := testService(t)
	s.now = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	calls := []string{}
	s.download = func(ctx context.Context, kind string, m time.Time) (*prepared, error) {
		calls = append(calls, kind+"/"+m.Format("2006-01"))
		if m.Month() == 11 {
			return nil, errNotPublished
		}
		return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, kind)))
	}
	if e := s.Enable(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(calls) != 4 || calls[0] != "city/2026-11" || calls[1] != "city/2026-10" || !s.Status().Enabled || s.Status().LastError != "" {
		t.Fatal(calls, s.Status())
	}
	if s.autoDue() {
		t.Fatal("retrying same day")
	}
	s.now = func() time.Time { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) }
	if !s.autoDue() {
		t.Fatal("pending month not retried")
	}
	old := s.snapshot()
	calls = nil
	if e := s.Update(context.Background()); e != nil || len(calls) != 2 || s.snapshot().City.File != old.City.File {
		t.Fatal(e, calls)
	}
	// City ready but ASN corrupt: neither reader nor persisted manifest may switch.
	s.download = func(ctx context.Context, kind string, _ time.Time) (*prepared, error) {
		if kind == "asn" {
			return nil, errors.New("corrupt")
		}
		return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, "city-other")))
	}
	if e := s.Update(context.Background()); e == nil {
		t.Fatal("partial pair committed")
	}
	if s.Lookup("8.8.8.8").CountryCode != "CN" || s.snapshot().City.File != old.City.File {
		t.Fatal("pair rollback")
	}
	if s.autoDue() {
		t.Fatal("failure retry must be throttled")
	}
	upload(t, s, "city", "city-other")
	var kinds []string
	s.download = func(ctx context.Context, kind string, _ time.Time) (*prepared, error) {
		kinds = append(kinds, kind)
		return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, kind)))
	}
	if e := s.Update(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(kinds) != 1 || kinds[0] != "asn" || s.Lookup("8.8.8.8").CountryCode != "US" {
		t.Fatal("overwrote upload", kinds)
	}
	if s.autoDue() {
		t.Fatal("month already checked")
	}
	if s.Status().Attribution == "" {
		t.Fatal("missing attribution")
	}
}
func TestNoNetworkUntilEnabledAndUnavailableFirstMonth(t *testing.T) {
	s := testService(t)
	calls := 0
	s.download = func(context.Context, string, time.Time) (*prepared, error) { calls++; return nil, errNotPublished }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Run(ctx)
	if calls != 0 || s.autoDue() {
		t.Fatal("default network")
	}
	if e := s.Enable(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s.Status().Enabled || s.Status().LastError != "" || calls != 4 {
		t.Fatal(s.Status(), calls)
	}
}

func TestManifestFailurePreservesReaderAndCleansTemporaryGeneration(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	statePath := filepath.Join(s.dir, "state.json")
	original, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(statePath); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(statePath, 0700); e != nil {
		t.Fatal(e)
	}
	if e = s.Upload(context.Background(), "city", bytes.NewReader(fixture(t, "city-other"))); e == nil {
		t.Fatal("manifest failure ignored")
	}
	if got := s.Lookup("8.8.8.8"); got.CountryCode != "CN" {
		t.Fatal("reader switched before atomic rename", got)
	}
	_ = os.Remove(statePath)
	if e = os.WriteFile(statePath, original, 0600); e != nil {
		t.Fatal(e)
	}
	files, _ := os.ReadDir(s.dir)
	if len(files) != 2 {
		t.Fatalf("failed generation leaked: %v", files)
	}
	again, e := New(filepath.Dir(s.dir))
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if again.Lookup("8.8.8.8").CountryCode != "CN" {
		t.Fatal("old manifest lost")
	}
}
func TestCrashRecoveryRemovesOnlyUnreferencedFiles(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	for _, name := range []string{"db-orphan.mmdb", "state-orphan", "unrelated"} {
		if e := os.WriteFile(filepath.Join(s.dir, name), []byte("orphan"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	again, e := New(filepath.Dir(s.dir))
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	for _, name := range []string{"db-orphan.mmdb", "state-orphan"} {
		if _, e = os.Stat(filepath.Join(s.dir, name)); !os.IsNotExist(e) {
			t.Fatal("orphan left", name)
		}
	}
	if _, e = os.Stat(filepath.Join(s.dir, "unrelated")); e != nil {
		t.Fatal(e)
	}
	if again.Lookup("8.8.8.8").City != "上海" {
		t.Fatal("live file removed")
	}
}

func TestStartupCorruptionDegradesWithoutDeletingFilesAndCanRecover(t *testing.T) {
	for _, damage := range []string{"state", "mmdb", "type"} {
		for _, recovery := range []string{"upload", "enable", "delete"} {
			t.Run(damage+"/"+recovery, func(t *testing.T) {
				original := testService(t)
				upload(t, original, "city", "city")
				upload(t, original, "asn", "asn")
				cityPath := filepath.Join(original.dir, original.snapshot().City.File)
				if e := original.Close(); e != nil {
					t.Fatal(e)
				}
				switch damage {
				case "state":
					if e := os.WriteFile(filepath.Join(original.dir, "state.json"), []byte(`{"enabled":true,broken`), 0600); e != nil {
						t.Fatal(e)
					}
				case "mmdb":
					if e := os.WriteFile(cityPath, []byte("broken mmdb"), 0600); e != nil {
						t.Fatal(e)
					}
				case "type":
					if e := os.WriteFile(cityPath, fixture(t, "asn"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				if e := os.WriteFile(filepath.Join(original.dir, "db-retained.mmdb"), []byte("retained"), 0600); e != nil {
					t.Fatal(e)
				}
				before := map[string][]byte{}
				files, e := os.ReadDir(original.dir)
				if e != nil {
					t.Fatal(e)
				}
				for _, f := range files {
					b, e := os.ReadFile(filepath.Join(original.dir, f.Name()))
					if e != nil {
						t.Fatal(e)
					}
					before[f.Name()] = b
				}
				s, e := New(filepath.Dir(original.dir))
				if e != nil {
					t.Fatalf("optional IP database prevented startup: %v", e)
				}
				defer s.Close()
				if s.Status().Enabled || s.Status().LastError == "" || s.Lookup("8.8.8.8") != nil || len(s.LookupBatch([]string{"8.8.8.8", "127.0.0.1"})) != 0 {
					t.Fatal("database failure was not reported", s.Status())
				}
				for name, want := range before {
					got, e := os.ReadFile(filepath.Join(s.dir, name))
					if e != nil || !bytes.Equal(got, want) {
						t.Fatalf("startup changed retained file %s: %v", name, e)
					}
				}
				switch recovery {
				case "upload":
					upload(t, s, "city", "city-other")
					if got := s.Lookup("8.8.8.8"); got == nil || got.CountryCode != "US" {
						t.Fatal("upload recovery failed", got)
					}
				case "enable":
					s.download = func(ctx context.Context, kind string, _ time.Time) (*prepared, error) {
						return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, kind)))
					}
					if e = s.Enable(context.Background()); e != nil {
						t.Fatal(e)
					}
					if got := s.Lookup("8.8.8.8"); got == nil || got.CountryCode != "CN" || got.ASN != 64500 {
						t.Fatal("enable recovery failed", got)
					}
				case "delete":
					if e = s.Delete(context.Background()); e != nil {
						t.Fatal(e)
					}
					if s.Status().Enabled || s.Lookup("8.8.8.8") != nil {
						t.Fatal("delete recovery failed")
					}
				}
				if s.Status().LastError != "" {
					t.Fatal("recovery left error", s.Status())
				}
				restored, e := New(filepath.Dir(s.dir))
				if e != nil {
					t.Fatal(e)
				}
				defer restored.Close()
				if recovery != "delete" && !restored.Status().Enabled {
					t.Fatal("recovery not persisted", restored.Status())
				}
			})
		}
	}
}

func TestStartupOnlyOpensMetadataButUploadsStillFullyVerify(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city")
	path := filepath.Join(s.dir, s.snapshot().City.File)
	raw := fixture(t, "city")
	// Keep valid metadata but corrupt one tree pointer. Opening metadata is O(1),
	// while Verify must reject the tree. Boot must not scan every record.
	raw[0], raw[1], raw[2] = 0xff, 0xff, 0xff
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if r, e := validate(path, "city"); e == nil {
		_ = r.Close()
		t.Fatal("full validation did not reject the broken tree")
	}
	booted, e := New(filepath.Dir(s.dir))
	if e != nil {
		t.Fatal(e)
	}
	defer booted.Close()
	if !booted.Status().Enabled {
		t.Fatal("startup performed full content verification", booted.Status())
	}
	if booted.Lookup("8.8.8.8") != nil || booted.Status().Enabled || booted.Status().LastError != string(errInvalidContent) {
		t.Fatal("query-time corruption did not disable enrichment", booted.Status())
	}
	if kept, e := os.ReadFile(path); e != nil || !bytes.Equal(kept, raw) {
		t.Fatal("lazy corruption recovery deleted or rewrote library", e)
	}
	target := testService(t)
	if e = target.Upload(context.Background(), "city", bytes.NewReader(raw)); e == nil {
		t.Fatal("upload skipped full validation")
	}
	if target.Lookup("8.8.8.8") != nil {
		t.Fatal("broken upload enabled")
	}
}

func TestStartupSanitizesStoredLastError(t *testing.T) {
	dir := t.TempDir()
	if e := os.MkdirAll(filepath.Join(dir, "ipdb"), 0700); e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"enabled":false,"last_error":"read /private/server/path: connection refused https://internal.example"}`)
	if e := os.WriteFile(filepath.Join(dir, "ipdb", "state.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Status().LastError != genericError {
		t.Fatal("unsafe stored error", s.Status())
	}
}

func TestUnreadableStateDoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "ipdb")
	statePath := filepath.Join(dbDir, "state.json")
	// A directory is unreadable as a state file even when tests run as root.
	if e := os.MkdirAll(statePath, 0700); e != nil {
		t.Fatal(e)
	}
	kept := filepath.Join(dbDir, "db-retained.mmdb")
	if e := os.WriteFile(kept, fixture(t, "city"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(dir)
	if e != nil {
		t.Fatal("state read error blocked startup", e)
	}
	defer s.Close()
	if s.Status().Enabled || s.Status().LastError != string(errUnreadableState) || s.Lookup("8.8.8.8") != nil {
		t.Fatal(s.Status())
	}
	if _, e = os.Stat(kept); e != nil {
		t.Fatal("read failure removed old file", e)
	}
}

func TestPublicDBIPAttributionEligibility(t *testing.T) {
	var absent *Service
	if absent.UsesDBIP() {
		t.Fatal("nil library attributed")
	}
	s := testService(t)
	if s.UsesDBIP() {
		t.Fatal("disabled library attributed")
	}
	upload(t, s, "city", "city")
	if s.UsesDBIP() {
		t.Fatal("uploaded library attributed")
	}
	s.op.Lock()
	p, e := s.prepare(context.Background(), "asn", "db-ip", bytes.NewReader(fixture(t, "asn")))
	if e != nil {
		s.op.Unlock()
		t.Fatal(e)
	}
	e = s.commit(context.Background(), s.snapshot(), map[string]*prepared{"asn": p})
	s.op.Unlock()
	if e != nil {
		p.discard()
		t.Fatal(e)
	}
	if !s.UsesDBIP() {
		t.Fatal("mixed DB-IP library missing attribution")
	}
	if e = s.Delete(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s.UsesDBIP() {
		t.Fatal("deleted library attributed")
	}
}
