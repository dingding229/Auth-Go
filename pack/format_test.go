package pack

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() string {
	b, _ := json.Marshal(map[string]any{"url": "https://auth.example.test", "app_key": "app_test", "app_secret": "public-test-config", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "gateway_key": b64.EncodeToString(make([]byte, 32))})
	return "authgo2." + b64.EncodeToString(b)
}
func fixture(t *testing.T, sizes ...int64) (Payload, []byte, []byte) {
	t.Helper()
	priv := bytes.Repeat([]byte{0x23}, 32)
	k, e := ecdh.X25519().NewPrivateKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{}
	for i, n := range sizes {
		m.Files = append(m.Files, File{Name: "file" + strconv.Itoa(i), Kind: "node", Path: cipherName(i), Size: n, ChunkSize: ChunkSize, Encoding: "raw"})
	}
	m = testWatermarkManifest(m)
	p, key, e := NewPayload(Payload{AppKey: "app_test", Version: "1.2.3-rc.1+test", BuiltAt: "2026-11-07T00:00:00Z", KeyID: "key-1", Config: testConfig()}, m, k.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	return p, key, priv
}
func seal(t *testing.T, p Payload, key []byte, file uint32, data []byte) []byte {
	t.Helper()
	b, e := binding(p)
	if e != nil {
		t.Fatal(e)
	}
	var w bytes.Buffer
	if e = encrypt(&w, bytes.NewReader(data), int64(len(data)), key, b, file); e != nil {
		t.Fatal(e)
	}
	return w.Bytes()
}
func TestRoundTripAndRandomAccess(t *testing.T) {
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 7, 2 * ChunkSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			p, key, priv := fixture(t, int64(size))
			got, e := Unlock(p, priv)
			if e != nil || !bytes.Equal(got, key) {
				t.Fatal("unlock", e)
			}
			plain := bytes.Repeat([]byte{0xa5}, size)
			enc := seal(t, p, key, 0, plain)
			if int64(len(enc)) != CipherSize(int64(size)) {
				t.Fatal("size")
			}
			var decoded []byte
			for i := uint64(0); i < uint64(chunkCount(int64(size))); i++ {
				r := &oneRead{data: enc, offset: int64(i) * (ChunkSize + 16), t: t}
				b, e := ReadChunk(r, int64(len(enc)), p, key, 0, i)
				if e != nil {
					t.Fatal(e)
				}
				decoded = append(decoded, b...)
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatal("plaintext")
			}
		})
	}
}

type oneRead struct {
	data   []byte
	offset int64
	t      *testing.T
}

func (r *oneRead) ReadAt(b []byte, off int64) (int, error) {
	if off != r.offset {
		r.t.Fatalf("read preceding block at %d", off)
	}
	return bytes.NewReader(r.data).ReadAt(b, off)
}
func TestEnvelopeBindings(t *testing.T) {
	p, key, priv := fixture(t, 5)
	enc := seal(t, p, key, 0, []byte("hello"))
	changes := map[string]func(*Payload){"app_key": func(p *Payload) { p.AppKey = "other" }, "version": func(p *Payload) { p.Version = "1.2.4" }, "built_at": func(p *Payload) { p.BuiltAt = "2026-11-08T00:00:00Z" }, "key_id": func(p *Payload) { p.KeyID = "key-2" }, "config": func(p *Payload) {
		raw, _ := b64.DecodeString(strings.TrimPrefix(p.Config, "authgo2."))
		var c map[string]any
		json.Unmarshal(raw, &c)
		c["url"] = "https://another.example.test"
		raw, _ = json.Marshal(c)
		p.Config = "authgo2." + b64.EncodeToString(raw)
	}, "manifest": func(p *Payload) {
		raw, _ := b64.DecodeString(p.Manifest)
		p.Manifest = b64.EncodeToString(append(raw, ' '))
	}, "v": func(p *Payload) { p.V = 3 }, "ephemeral": func(p *Payload) { p.Envelope.E = b64.EncodeToString(bytes.Repeat([]byte{1}, 32)) }, "nonce": func(p *Payload) { p.Envelope.N = b64.EncodeToString(bytes.Repeat([]byte{1}, 12)) }, "ciphertext": func(p *Payload) { p.Envelope.C = b64.EncodeToString(bytes.Repeat([]byte{1}, 48)) }}
	for n, change := range changes {
		t.Run(n, func(t *testing.T) {
			bad := p
			change(&bad)
			if _, e := Unlock(bad, priv); e == nil {
				t.Fatal("accepted tampered envelope")
			}
			if _, e := ReadChunk(bytes.NewReader(enc), int64(len(enc)), bad, key, 0, 0); e == nil {
				t.Fatal("accepted tampered binding")
			}
		})
	}
	// Valid metadata changes (not just schema failures) also fail authentication.
	raw, _ := b64.DecodeString(p.Manifest)
	var m Manifest
	json.Unmarshal(raw, &m)
	for _, field := range []string{"name", "kind", "size", "encoding", "path", "chunk_size"} {
		t.Run("manifest_"+field, func(t *testing.T) {
			var obj map[string]any
			json.Unmarshal(raw, &obj)
			f := obj["files"].([]any)[0].(map[string]any)
			switch field {
			case "size":
				f[field] = 6
			case "chunk_size":
				f[field] = 512
			case "kind":
				f[field] = "java"
			case "path":
				f[field] = "../escape"
			case "encoding":
				f[field] = "tar"
			default:
				f[field] = "renamed"
			}
			b, _ := json.Marshal(obj)
			bad := p
			bad.Manifest = b64.EncodeToString(b)
			if _, e := Unlock(bad, priv); e == nil {
				t.Fatal("accepted manifest change")
			}
		})
	}
	if _, e := Unlock(p, make([]byte, 32)); e == nil {
		t.Fatal("wrong recipient")
	}
	if _, e := ReadChunk(bytes.NewReader(enc), int64(len(enc)), p, make([]byte, 32), 0, 0); e == nil {
		t.Fatal("wrong key")
	}
}
func TestChunkAttackCases(t *testing.T) {
	plain := bytes.Repeat([]byte{0x32}, ChunkSize+5)
	p, key, _ := fixture(t, int64(len(plain)), int64(len(plain)))
	a := seal(t, p, key, 0, plain)
	b := seal(t, p, key, 1, plain)
	reject := func(name string, c []byte, file uint32, chunk uint64) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, e := ReadChunk(bytes.NewReader(c), int64(len(c)), p, key, file, chunk); e == nil {
				t.Fatal("attack accepted")
			}
		})
	}
	reject("other_file", b, 0, 0)
	for _, n := range []int{0, 1, 16, ChunkSize, ChunkSize + 16, len(a) - 1} {
		reject("truncate_"+strconv.Itoa(n), a[:n], 0, 0)
	}
	reject("extra", append(append([]byte{}, a...), 0), 0, 0)
	changed := append([]byte{}, a...)
	changed[0] ^= 1
	reject("bit", changed, 0, 0)
	swapped := append(append([]byte{}, a[ChunkSize+16:]...), a[:ChunkSize+16]...)
	reject("reorder_first", swapped, 0, 0)
	reject("reorder_last", swapped, 0, 1)
	// Same content key but a fresh authenticated envelope: cross-build substitution.
	other := p
	pubKey, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x23}, 32))
	if e := wrap(&other, key, pubKey.PublicKey().Bytes(), bytes.NewReader(bytes.Repeat([]byte{0x55}, 256))); e != nil {
		t.Fatal(e)
	}
	bind, _ := binding(other)
	var w bytes.Buffer
	encrypt(&w, bytes.NewReader(plain), int64(len(plain)), key, bind, 0)
	reject("other_build_same_key", w.Bytes(), 0, 0)
	bind, _ = binding(p)
	g, _ := aead(key)
	wrongLast := g.Seal(nil, nonce(0, 1), plain[ChunkSize:], chunkAAD(bind, 0, 1, false))
	wrong := append(append([]byte{}, a[:ChunkSize+16]...), wrongLast...)
	reject("last_flag", wrong, 0, 1)
	wrongIndex := g.Seal(nil, nonce(0, 0), plain[:ChunkSize], chunkAAD(bind, 0, 1, false))
	wrong = append(append([]byte{}, wrongIndex...), a[ChunkSize+16:]...)
	reject("chunk_index_aad", wrong, 0, 0)
	wrongFile := g.Seal(nil, nonce(0, 0), plain[:ChunkSize], chunkAAD(bind, 1, 0, false))
	wrong = append(append([]byte{}, wrongFile...), a[ChunkSize+16:]...)
	reject("file_index_aad", wrong, 0, 0)
	empty, ek, _ := fixture(t, 0)
	c := seal(t, empty, ek, 0, nil)
	if len(c) != 16 {
		t.Fatal("empty tag missing")
	}
	if _, e := ReadChunk(bytes.NewReader(nil), 0, empty, ek, 0, 0); e == nil {
		t.Fatal("zero truncation accepted")
	}
	if _, e := ReadChunk(bytes.NewReader(a), int64(len(a)), p, key, 2, 0); e == nil {
		t.Fatal("file range")
	}
	if _, e := ReadChunk(bytes.NewReader(a), int64(len(a)), p, key, 0, 2); e == nil {
		t.Fatal("chunk range")
	}
}
func rssKiB() uint64 {
	b, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n
		}
	}
	return 0
}
func TestStreaming2GiB(t *testing.T) {
	// No skip/short shortcut: actual 2 GiB input and on-disk ciphertext, removed
	// by TempDir cleanup even on failure. Sparse input is read in its entirety.
	type measurement struct{ heap, rss uint64 }
	var measurements []measurement
	for _, size := range []int64{8 << 20, 2 << 30} {
		dir := t.TempDir()
		in, e := os.Create(filepath.Join(dir, "input"))
		if e != nil {
			t.Fatal(e)
		}
		if e = in.Truncate(size); e != nil {
			t.Fatal(e)
		}
		defer in.Close()
		out, e := os.Create(filepath.Join(dir, "cipher"))
		if e != nil {
			t.Fatal(e)
		}
		defer out.Close()
		runtime.GC()
		var mu sync.Mutex
		peak := measurement{}
		done := make(chan struct{})
		finished := make(chan struct{})
		sample := func() {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			r := rssKiB()
			mu.Lock()
			peak.heap = max(peak.heap, m.HeapAlloc)
			peak.rss = max(peak.rss, r)
			mu.Unlock()
		}
		go func() {
			defer close(finished)
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-tick.C:
					sample()
				case <-done:
					return
				}
			}
		}()
		p, key, _ := fixture(t, size)
		bind, _ := binding(p)
		sample()
		e = encrypt(out, in, size, key, bind, 0)
		if e != nil {
			close(done)
			<-finished
			t.Fatal(e)
		}
		if e = out.Sync(); e != nil {
			t.Fatal(e)
		}
		st, _ := out.Stat()
		for i := uint64(0); i < uint64(chunkCount(size)); i++ {
			b, e := ReadChunk(out, st.Size(), p, key, 0, i)
			if e != nil {
				t.Fatal(e)
			}
			for _, v := range b {
				if v != 0 {
					t.Fatal("corrupt plaintext")
				}
			}
		}
		sample()
		close(done)
		<-finished
		measurements = append(measurements, peak)
		t.Logf("size=%d peak_heap=%d bytes peak_RSS=%d KiB", size, peak.heap, peak.rss)
		if peak.heap > 64<<20 || peak.rss > 128<<10 {
			t.Fatalf("memory is not bounded: %+v", peak)
		}
		out.Close()
		in.Close()
		if e = os.RemoveAll(dir); e != nil {
			t.Fatal(e)
		}
	}
	if measurements[1].heap > measurements[0].heap+16<<20 {
		t.Fatal("heap grew with input size")
	}
}

var writeVector = flag.Bool("write-vector", false, "regenerate public synthetic test fixture")

func TestVector(t *testing.T) {
	recipient := bytes.Repeat([]byte{0x23}, 32)
	priv, _ := ecdh.X25519().NewPrivateKey(recipient)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	m := Manifest{Files: []File{{Name: "empty", Kind: "node", Path: cipherName(0), Size: 0, ChunkSize: ChunkSize, Encoding: "raw"}, {Name: "multi", Kind: "node", Path: cipherName(1), Size: ChunkSize + 5, ChunkSize: ChunkSize, Encoding: "raw"}}}
	m = testWatermarkManifest(m)
	raw, _ := json.Marshal(m)
	p := Payload{V: 2, AppKey: "app_test", Version: "1.2.3", BuiltAt: "2026-11-07T00:00:00Z", KeyID: "key-1", Config: testConfig(), Manifest: b64.EncodeToString(raw)}
	if e := wrap(&p, key, priv.PublicKey().Bytes(), bytes.NewReader(bytes.Repeat([]byte{0x41}, 256))); e != nil {
		t.Fatal(e)
	}
	a, _ := p.aad()
	epub, _ := b64.DecodeString(p.Envelope.E)
	a = append(a, epub...)
	salt := sha256.Sum256(a)
	ep, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x41}, 32))
	shared, _ := ep.ECDH(priv.PublicKey())
	kek, _ := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/wrap", 32)
	bind, _ := binding(p)
	plain := append(bytes.Repeat([]byte{0x41}, ChunkSize), []byte("hello")...)
	multi := seal(t, p, key, 1, plain)
	empty := seal(t, p, key, 0, nil)
	hash := sha256.Sum256(multi[:ChunkSize+16])
	g, _ := aead(key)
	vec := map[string]any{"notice": "PUBLIC SYNTHETIC TEST KEYS ONLY; never use in production", "payload": p, "recipient_private_hex": hex.EncodeToString(recipient), "recipient_public_hex": hex.EncodeToString(priv.PublicKey().Bytes()), "ephemeral_private_hex": strings.Repeat("41", 32), "content_key_hex": hex.EncodeToString(key), "manifest_utf8": string(raw), "envelope_aad_hex": hex.EncodeToString(a), "salt_hex": hex.EncodeToString(salt[:]), "shared_hex": hex.EncodeToString(shared), "kek_hex": hex.EncodeToString(kek), "binding_hex": hex.EncodeToString(bind), "chunks": []any{map[string]any{"file": 0, "chunk": 0, "last": true, "plain_hex": "", "nonce_hex": hex.EncodeToString(nonce(0, 0)), "aad_hex": hex.EncodeToString(chunkAAD(bind, 0, 0, true)), "cipher_hex": hex.EncodeToString(empty)}, map[string]any{"file": 1, "chunk": 0, "last": false, "plain_repeat_hex": "41", "plain_repeat_count": ChunkSize, "nonce_hex": hex.EncodeToString(nonce(1, 0)), "aad_hex": hex.EncodeToString(chunkAAD(bind, 1, 0, false)), "cipher_sha256_hex": hex.EncodeToString(hash[:]), "cipher_first32_hex": hex.EncodeToString(multi[:32]), "tag_hex": hex.EncodeToString(multi[ChunkSize : ChunkSize+g.Overhead()])}, map[string]any{"file": 1, "chunk": 1, "last": true, "plain_hex": hex.EncodeToString([]byte("hello")), "nonce_hex": hex.EncodeToString(nonce(1, 1)), "aad_hex": hex.EncodeToString(chunkAAD(bind, 1, 1, true)), "cipher_hex": hex.EncodeToString(multi[ChunkSize+16:])}}}
	b, _ := json.MarshalIndent(vec, "", "  ")
	b = append(b, '\n')
	file := "../sdk/vectors/payload-envelope.json"
	if *writeVector {
		if e := os.WriteFile(file, b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	want, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, want) {
		t.Fatal("cross-language vector mismatch")
	}
	got, e := Unlock(p, recipient)
	if e != nil || !bytes.Equal(got, key) {
		t.Fatal("vector unlock")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestStreamIOFailures(t *testing.T) {
	p, key, _ := fixture(t, 3)
	bind, _ := binding(p)
	if encrypt(shortWriter{}, bytes.NewReader([]byte("abc")), 3, key, bind, 0) == nil {
		t.Fatal("short write accepted")
	}
	for _, data := range []string{"ab", "abcd"} {
		var out bytes.Buffer
		if encrypt(&out, bytes.NewReader([]byte(data)), 3, key, bind, 0) == nil {
			t.Fatal("changed source size accepted")
		}
	}
	if wrap(&p, key, make([]byte, 32), bytes.NewReader(nil)) == nil {
		t.Fatal("random failure accepted")
	}
}

func TestEphemeralEncodingMalleability(t *testing.T) {
	p, _, priv := fixture(t, 0)
	e, _ := b64.DecodeString(p.Envelope.E)
	e[31] ^= 0x80
	p.Envelope.E = b64.EncodeToString(e)
	// X25519 masks this high bit. It must still fail envelope authentication.
	if _, err := Unlock(p, priv); err == nil {
		t.Fatal("equivalent X25519 encoding was not AAD-bound")
	}
}

func TestProtectedConfigRedirectCannotUnlockEnvelope(t *testing.T) {
	p, key, private := fixture(t, 16)
	original, e := Unlock(p, private)
	if e != nil || !bytes.Equal(original, key) {
		t.Fatal("control", e)
	}
	config, _ := b64.DecodeString(strings.TrimPrefix(p.Config, "authgo2."))
	var fields map[string]any
	json.Unmarshal(config, &fields)
	fields["url"] = "https://fake.example.test"
	raw, _ := json.Marshal(fields)
	p.Config = "authgo2." + b64.EncodeToString(raw)
	if e := validateConfig(p.Config, p.AppKey); e != nil {
		t.Fatal("redirect fixture must be a valid pinned HTTPS config", e)
	}
	// Even the original packing key cannot authenticate an altered config/AAD.
	if _, e = Unlock(p, private); e == nil {
		t.Fatal("redirected config accepted")
	}
	// A fake service with its own pack/signing keys cannot recover the old DEK.
	if _, e = Unlock(p, bytes.Repeat([]byte{0x39}, 32)); e == nil {
		t.Fatal("fake service recovered original key")
	}
}

// Cryptographic fixtures use the same manifest shape as current watermarked builds.
func testWatermarkManifest(m Manifest) Manifest {
	for _, f := range m.Files {
		if f.Kind == "watermark" {
			return m
		}
	}
	m.Files = append(m.Files, File{Name: watermarkIndexName, Kind: "watermark", Path: cipherName(len(m.Files)), Size: 1, ChunkSize: ChunkSize, Encoding: "raw"})
	return m
}
