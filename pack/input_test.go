package pack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func put(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0700); e != nil {
		t.Fatal(e)
	}
}
func jar(t *testing.T, p string, names []string) {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, n := range names {
		w, e := z.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if n == "META-INF/MANIFEST.MF" {
			io.WriteString(w, "Manifest-Version: 1.0\r\nMain-Class: example.\r\n Main\r\n\r\n")
		} else {
			io.WriteString(w, "code")
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	put(t, p, buf.Bytes())
}
func elfBytes(machine uint16) []byte {
	b := make([]byte, 120)
	copy(b, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint64(b[24:], 0x400000)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	binary.LittleEndian.PutUint64(b[80:], 0x400000)
	binary.LittleEndian.PutUint64(b[96:], 120)
	binary.LittleEndian.PutUint64(b[104:], 120)
	return b
}
func managedPE() []byte {
	b := make([]byte, 1024)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 128)
	copy(b[128:], "PE\x00\x00")
	h := b[132:]
	binary.LittleEndian.PutUint16(h, 0x14c)
	binary.LittleEndian.PutUint16(h[2:], 1)
	binary.LittleEndian.PutUint16(h[16:], 224)
	o := b[152:]
	binary.LittleEndian.PutUint16(o, 0x10b)
	binary.LittleEndian.PutUint32(o[92:], 16)
	binary.LittleEndian.PutUint32(o[96+14*8:], 0x2000)
	binary.LittleEndian.PutUint32(o[100+14*8:], 72)
	s := b[376:]
	copy(s, ".text")
	binary.LittleEndian.PutUint32(s[8:], 512)
	binary.LittleEndian.PutUint32(s[12:], 0x2000)
	binary.LittleEndian.PutUint32(s[16:], 512)
	binary.LittleEndian.PutUint32(s[20:], 512)
	binary.LittleEndian.PutUint32(b[512:], 72)
	binary.LittleEndian.PutUint32(b[520:], 0x2080)
	binary.LittleEndian.PutUint32(b[524:], 16)
	binary.LittleEndian.PutUint32(b[528:], 1)
	copy(b[640:], "BSJB")
	return b
}
func TestInputTypes(t *testing.T) {
	d := t.TempDir()
	node := filepath.Join(d, "core.cjs")
	put(t, node, []byte("module.exports=42;"))
	j := filepath.Join(d, "app.jar")
	jar(t, j, []string{"META-INF/MANIFEST.MF", "example/Main.class"})
	dll := filepath.Join(d, "App.dll")
	put(t, dll, managedPE())
	deps := filepath.Join(d, "App.deps.json")
	put(t, deps, []byte(`{"runtimeTarget":{"name":"test"}}`))
	py := filepath.Join(d, "py")
	php := filepath.Join(d, "php")
	os.Mkdir(py, 0700)
	os.Mkdir(php, 0700)
	pyc := make([]byte, 18)
	copy(pyc, []byte{0xa7, 0x0d, 13, 10})
	put(t, filepath.Join(py, "mod.pyc"), pyc)
	put(t, filepath.Join(php, "index.php"), []byte("<?php echo 42;"))
	put(t, filepath.Join(php, "data.txt"), []byte("data"))
	for kind, p := range map[string]string{"node": node, "java": j, "dotnet": dll, "python": py, "php": php} {
		t.Run(kind, func(t *testing.T) {
			s, e := inspect(kind, "app", p)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "python" && s.file.PythonVersion != "3.11" {
				t.Fatal("Python version")
			}
			if kind == "java" && s.file.MainClass != "example.Main" {
				t.Fatal("main class")
			}
			r, e := s.reader()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			b, e := io.ReadAll(r)
			if e != nil || int64(len(b)) != s.file.Size {
				t.Fatal("stream size", e)
			}
			if s.file.Encoding == "tar" {
				tr := tar.NewReader(bytes.NewReader(b))
				count := 0
				for {
					h, e := tr.Next()
					if e == io.EOF {
						break
					}
					if e != nil || !safeEntry(h.Name) || h.Typeflag != tar.TypeReg {
						t.Fatal("archive", e)
					}
					count++
				}
				want := 1
				if kind == "dotnet" {
					want = 2
				}
				if count != want {
					t.Fatal("archive entry count", count)
				}
			}
		})
	}
	for _, arch := range []struct {
		m uint16
		s string
	}{{62, "amd64"}, {183, "arm64"}} {
		f := filepath.Join(d, arch.s)
		put(t, f, elfBytes(arch.m))
		s, e := inspect("protect", "protect", f)
		if e != nil || s.file.Architecture != arch.s {
			t.Fatal(e)
		}
	}
}
func TestRejectInputTypesAndPaths(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "x.cjs")
	put(t, file, []byte("module.exports=1;"))
	for _, name := range []string{"", "../x", "/x", "UPPER", "a.b", "a/b", "a\\b", "a:b", strings.Repeat("a", 129)} {
		if _, e := inspect("node", name, file); e == nil {
			t.Fatalf("name accepted %q", name)
		}
	}
	for _, n := range []string{"../x", "/x", "a/../x", "a//x", "a/./x", "a\\x", "C:x", "a\x00b"} {
		if safeEntry(n) {
			t.Fatalf("entry accepted %q", n)
		}
	}
	cases := []struct {
		kind, filename string
		b              []byte
	}{{"node", "native.cjs", []byte("require( 'x.node' )")}, {"node", "esm.cjs", []byte("export default 1")}, {"node", "esm.mjs", []byte("module.exports=1")}, {"java", "broken.jar", []byte("not zip")}, {"dotnet", "native.dll", []byte("native")}, {"protect", "bad", []byte("noelf")}, {"protect", "arch", elfBytes(40)}}
	native := managedPE()
	binary.LittleEndian.PutUint32(native[528:], 0)
	cases = append(cases, struct {
		kind, filename string
		b              []byte
	}{"dotnet", "mixed.dll", native})
	for _, c := range cases {
		f := filepath.Join(d, c.filename)
		put(t, f, c.b)
		if _, e := inspect(c.kind, "app", f); e == nil {
			t.Fatal("accepted", c.filename)
		}
	}
	for _, kind := range []string{"php", "python"} {
		if _, e := inspect(kind, "app", file); e == nil {
			t.Fatal("directory required")
		}
	}
	if _, e := inspect("node", "app", d); e == nil {
		t.Fatal("file required")
	}
	sym := filepath.Join(d, "symlink.cjs")
	if e := os.Symlink(file, sym); e != nil {
		t.Fatal(e)
	}
	if _, e := inspect("node", "app", sym); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Mkdir(filepath.Join(d, "dir"), 0700)
	os.Symlink(filepath.Join(d, "dir"), filepath.Join(d, "alias"))
	put(t, filepath.Join(d, "dir", "code.cjs"), []byte("module.exports=1"))
	if _, e := inspect("node", "app", filepath.Join(d, "alias", "code.cjs")); e == nil {
		t.Fatal("ancestor symlink accepted")
	}
	dir := filepath.Join(d, "py")
	os.Mkdir(dir, 0700)
	for _, n := range []string{"native.so", "source.py", "bad.pyc"} {
		put(t, filepath.Join(dir, n), []byte("invalid"))
		if _, e := inspect("python", "app", dir); e == nil {
			t.Fatal("accepted", n)
		}
		os.Remove(filepath.Join(dir, n))
	}
	os.Symlink(file, filepath.Join(dir, "link"))
	if _, e := inspect("php", "app", dir); e == nil {
		t.Fatal("archive symlink accepted")
	}
	for i, n := range []string{"../evil.class", "/evil.class", "a\\evil.class"} {
		j := filepath.Join(d, string(rune('a'+i))+".jar")
		jar(t, j, []string{n})
		if _, e := inspect("java", "app", j); e == nil {
			t.Fatal("unsafe jar accepted")
		}
	}
	dll := filepath.Join(d, "Deps.dll")
	put(t, dll, managedPE())
	put(t, filepath.Join(d, "Deps.deps.json"), []byte(`{"targets":{"native":{}}}`))
	if _, e := inspect("dotnet", "app", dll); e == nil {
		t.Fatal("native dependency accepted")
	}
}
func cliArgs(t *testing.T, source, dest string) []string {
	t.Helper()
	_, _, priv := fixture(t, 0)
	k, _ := ecdhPrivate(priv)
	return []string{"--public-key", b64.EncodeToString(k), "--key-id", "key-1", "--app-key", "app_test", "--version", "1.2.3", "--config", testConfig(), "--node", "core=" + source, "--out", dest}
}
func ecdhPrivate(b []byte) ([]byte, error) {
	k, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return nil, e
	}
	return k.PublicKey().Bytes(), nil
}
func TestCLIAndTransactionalPublish(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1794009600")
	dir := t.TempDir()
	src := filepath.Join(dir, "core.cjs")
	put(t, src, []byte("module.exports=42;"))
	dest := filepath.Join(dir, "out")
	args := cliArgs(t, src, dest)
	var log bytes.Buffer
	if Run(args, &log, &log) != 0 {
		t.Fatal(log.String())
	}
	if _, e := os.Lstat(src); !os.IsNotExist(e) {
		t.Fatal("plaintext not removed")
	}
	if e := Verify(dest); e != nil {
		t.Fatal(e)
	}
	var p Payload
	b, _ := os.ReadFile(filepath.Join(dest, "payload.json"))
	if e := strictJSON(b, &p); e != nil {
		t.Fatal(e)
	}
	if p.BuiltAt != "2026-11-07T00:00:00Z" {
		t.Fatal(p.BuiltAt)
	}
	priv := bytes.Repeat([]byte{0x23}, 32)
	key, e := Unlock(p, priv)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := os.Open(filepath.Join(dest, cipherName(0)))
	defer f.Close()
	st, _ := f.Stat()
	plain, e := ReadChunk(f, st.Size(), p, key, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	// v2 intentionally adds real code constants. Preserve the old exact user-
	// code assertion after the known metadata statement, and additionally
	// authenticate/verify every inserted slot (not a relaxed plaintext check).
	end := bytes.Index(plain, []byte("];"))
	if p.V != 2 || end < 0 || !bytes.HasPrefix(plain, []byte(";void [")) || string(plain[end+2:]) != "module.exports=42;" {
		t.Fatal("user code changed outside watermark metadata")
	}
	metaFile, e := os.Open(filepath.Join(dest, cipherName(1)))
	if e != nil {
		t.Fatal(e)
	}
	metaStat, e := metaFile.Stat()
	if e != nil {
		t.Fatal(e)
	}
	metaRaw, e := ReadChunk(metaFile, metaStat.Size(), p, key, 1, 0)
	metaFile.Close()
	if e != nil {
		t.Fatal(e)
	}
	var index watermarkIndex
	if strictJSON(metaRaw, &index) != nil || index.V != "1" || len(index.Files) != 1 || len(index.Files[0].Entries) != 1 || len(index.Files[0].Entries[0].Offsets) != 8 {
		t.Fatal("missing authenticated slot metadata")
	}
	for _, text := range index.Files[0].Entries[0].Offsets {
		at, e := strconv.Atoi(text)
		if e != nil || at < 0 || at+96 > len(plain) || string(plain[at:at+96]) != index.Tag+strings.Repeat("0", 64) {
			t.Fatal("wrong slot binding")
		}
	}

	if Run([]string{"--verify", "--out", dest}, &log, &log) != 0 {
		t.Fatal(log.String())
	}
	bad := append([]byte{}, b...)
	bad = append(bad, []byte(`{}`)...)
	put(t, filepath.Join(dest, "payload.json"), bad)
	if Verify(dest) == nil {
		t.Fatal("trailing JSON")
	}
	put(t, filepath.Join(dest, "payload.json"), b)
	put(t, src, []byte("module.exports=original;"))
	before, _ := os.ReadFile(src)
	if Run(args, &log, &log) == 0 {
		t.Fatal("existing out overwritten")
	}
	after, _ := os.ReadFile(src)
	if !bytes.Equal(before, after) {
		t.Fatal("input changed on failure")
	}
	// Encrypting a second source that changed after inspection must not leave output.
	s, e := inspect("node", "core", src)
	if e != nil {
		t.Fatal(e)
	}
	s.file.Path = cipherName(0)
	p, key, _ = fixture(t, s.file.Size)
	put(t, src, []byte("changed"))
	failedDest := filepath.Join(dir, "failed")
	if e = publish(failedDest, []source{s}, p, key); e == nil {
		t.Fatal("source race accepted")
	}
	if _, e = os.Stat(failedDest); !os.IsNotExist(e) {
		t.Fatal("partial output")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".authgo-*"))
	if len(matches) != 0 {
		t.Fatal("temporary files", matches)
	}
}
func TestProtectReplacesELFWithTestLauncher(t *testing.T) {
	originalLoader := stubForArch
	loader := elfBytes(62)
	stubForArch = func(arch string) ([]byte, error) { return loader, nil }
	t.Cleanup(func() { stubForArch = originalLoader })
	dir := t.TempDir()
	src := filepath.Join(dir, "server")
	data := elfBytes(62)
	// Native v2 requires the SDK's eight distinct mapped placeholders. The
	// tiny test launcher remains separate and byte-for-byte asserted below.
	for i := 0; i < 8; i++ {
		data = append(data, watermarkPlaceholder(i)...)
	}
	binary.LittleEndian.PutUint64(data[96:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[104:], uint64(len(data)))
	put(t, src, data)
	args := cliArgs(t, "unused", filepath.Join(dir, "out"))
	for i := range args {
		if args[i] == "--node" {
			args[i] = "--protect"
			args[i+1] = src
			break
		}
	}
	var log bytes.Buffer
	if Run(args, &log, &log) != 0 {
		t.Fatal(log.String())
	}
	b, _ := os.ReadFile(src)
	if bytes.Equal(b, data) || !bytes.HasSuffix(b[len(b)-protectedFooterSize:], make([]byte, 16)) {
		t.Fatal("ELF was not replaced with a framed launcher")
	}
	if !bytes.Equal(b[:len(loader)], loader) || !bytes.Equal(b[len(b)-protectedFooterSize:len(b)-protectedFooterSize+16], protectedMagic[:]) {
		t.Fatal("launcher/footer missing")
	}
	if !strings.Contains(log.String(), "protected executable replaced") {
		t.Fatal("missing replacement result")
	}
	if Verify(filepath.Join(dir, "out")) != nil {
		t.Fatal("bad placeholder ciphertext")
	}
}
func TestParametersAndConfig(t *testing.T) {
	for _, v := range []string{"v1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3-", "1.2.3\n"} {
		if validVersion(v) {
			t.Fatal("bad semver", v)
		}
	}
	for _, v := range []string{"0.0.0", "1.2.3-0", "1.2.3-rc.1+build.00"} {
		if !validVersion(v) {
			t.Fatal("valid semver", v)
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "core.cjs")
	data := []byte("module.exports=1")
	put(t, src, data)
	for flag, value := range map[string]string{"--public-key": "secret-bad-key", "--key-id": "../id", "--app-key": "", "--version": "1.2", "--config": "secret-bad-config", "--node": "../escape=" + src, "--out": ""} {
		args := cliArgs(t, src, filepath.Join(dir, "out"))
		for i := range args {
			if args[i] == flag {
				args[i+1] = value
				break
			}
		}
		var log bytes.Buffer
		if Run(args, &log, &log) == 0 {
			t.Fatal("accepted", flag)
		}
		if strings.Contains(log.String(), "secret-bad") {
			t.Fatal("secret logged")
		}
		b, _ := os.ReadFile(src)
		if !bytes.Equal(b, data) {
			t.Fatal("input changed")
		}
	}
	for _, epoch := range []string{"-1", "1.5", "bad", "01", "9223372036854775807"} {
		t.Setenv("SOURCE_DATE_EPOCH", epoch)
		var b bytes.Buffer
		if Run(cliArgs(t, src, filepath.Join(dir, "out")), &b, &b) == 0 {
			t.Fatal("bad epoch")
		}
	}
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	args := cliArgs(t, src, filepath.Join(dir, "out"))
	args = append(args, "--node", "core="+src)
	if Run(args, io.Discard, io.Discard) == 0 {
		t.Fatal("duplicate names accepted")
	}
	for _, a := range [][]string{{"--unknown", "DO_NOT_LOG"}, {"--verify"}, {"--verify", "--out", dir, "--version", "1.2.3"}} {
		var b bytes.Buffer
		if Run(a, &b, &b) == 0 {
			t.Fatal("bad CLI")
		}
		if strings.Contains(b.String(), "DO_NOT_LOG") {
			t.Fatal("flag value leaked")
		}
	}
	raw := strings.TrimPrefix(testConfig(), "authgo2.")
	b, _ := b64.DecodeString(raw)
	var obj map[string]any
	json.Unmarshal(b, &obj)
	for _, field := range []string{"url", "public_key", "gateway_key", "app_key"} {
		old := obj[field]
		obj[field] = "bad"
		data, _ := json.Marshal(obj)
		if validateConfig("authgo2."+b64.EncodeToString(data), "app_test") == nil {
			t.Fatal("bad config", field)
		}
		obj[field] = old
	}
	for _, b := range []string{`{"v":1,"v":1}`, `{"files":null}`, `{"files":[]}`, `{"unknown":1}`} {
		var m Manifest
		if strictJSON([]byte(b), &m) == nil {
			if _, e := decodeManifest([]byte(b)); e == nil {
				t.Fatal("bad manifest")
			}
		}
	}
}

func TestRollbackAtCommitFailures(t *testing.T) {
	for _, stage := range []string{"second_input_rename", "output_rename", "output_fsync", "partial_cleanup", "cleanup_fsync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			var sources []source
			originals := map[string][]byte{}
			for i := 0; i < 2; i++ {
				path := filepath.Join(dir, fmt.Sprintf("input%d.cjs", i))
				data := []byte(fmt.Sprintf("module.exports=%d;", i))
				put(t, path, data)
				s, e := inspect("node", fmt.Sprintf("file%d", i), path)
				if e != nil {
					t.Fatal(e)
				}
				s.file.Path = cipherName(i)
				sources = append(sources, s)
				originals[path] = data
			}
			m := Manifest{}
			for _, s := range sources {
				m.Files = append(m.Files, s.file)
			}
			base, _, priv := fixture(t, 0)
			pub, _ := ecdhPrivate(priv)
			var e error
			sources, e = prepareWatermarkSources(sources, pub)
			if e != nil {
				t.Fatal(e)
			}
			m = Manifest{}
			for _, source := range sources {
				m.Files = append(m.Files, source.file)
			}
			p, key, e := NewPayload(base, m, pub)
			if e != nil {
				t.Fatal(e)
			}
			dest := filepath.Join(dir, "out")
			renameCalls, removeCalls, syncCalls := 0, 0, 0
			injected := errors.New("injected storage failure")
			fs := publicationFS{
				rename: func(a, b string) error {
					renameCalls++
					if stage == "second_input_rename" && renameCalls == 2 || stage == "output_rename" && renameCalls == 3 {
						return injected
					}
					return os.Rename(a, b)
				},
				remove: func(p string) error {
					removeCalls++
					if stage == "partial_cleanup" && removeCalls == 2 {
						return injected
					}
					return os.Remove(p)
				},
				sync: func(p string) error {
					syncCalls++
					if stage == "output_fsync" && syncCalls == 3 || stage == "cleanup_fsync" && syncCalls == 4 {
						return injected
					}
					return syncDir(p)
				},
			}
			if publishUsing(dest, sources, p, key, fs) == nil {
				t.Fatal("expected injected failure")
			}
			for path, want := range originals {
				got, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatal("original not restored", e)
				}
			}
			if _, e = os.Stat(dest); !os.IsNotExist(e) {
				t.Fatal("published failure residue")
			}
			slots, _ := filepath.Glob(filepath.Join(dir, ".authgo-*"))
			if len(slots) != 0 {
				t.Fatal("rollback residue", slots)
			}
		})
	}
}
func TestArchivePublishDeletesOnlyCode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "php")
	os.Mkdir(src, 0700)
	put(t, filepath.Join(src, "app.php"), []byte("<?php return 42;"))
	put(t, filepath.Join(src, "data.txt"), []byte("keep"))
	args := cliArgs(t, "unused", filepath.Join(dir, "out"))
	for i := range args {
		if args[i] == "--node" {
			args[i] = "--php"
			args[i+1] = "core=" + src
			break
		}
	}
	if Run(args, io.Discard, io.Discard) != 0 {
		t.Fatal("archive publish")
	}
	if _, e := os.Stat(filepath.Join(src, "app.php")); !os.IsNotExist(e) {
		t.Fatal("code remains")
	}
	if b, e := os.ReadFile(filepath.Join(src, "data.txt")); e != nil || string(b) != "keep" {
		t.Fatal("data removed")
	}
}
func TestCanonicalEncodings(t *testing.T) {
	for _, s := range []string{"AA=", "AA\n", "AA\r\n", "AB", "+A", "/A"} {
		if _, e := b64.DecodeString(s); e == nil {
			t.Fatal("noncanonical base64 accepted")
		}
	}
	var obj map[string]any
	for _, raw := range [][]byte{[]byte(`{"nested":{"x":1,"x":2}}`), {0xff}, []byte(`{} {}`)} {
		if strictJSON(raw, &obj) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestStrictPayloadSchema(t *testing.T) {
	p, _, _ := fixture(t, 0)
	raw, _ := json.Marshal(p)
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["V"] = m["v"]; delete(m, "v") },
		func(m map[string]any) { m["v"] = nil },
		func(m map[string]any) { m["app_key"] = nil },
		func(m map[string]any) { delete(m, "version") },
		func(m map[string]any) {
			m["envelope"].(map[string]any)["N"] = m["envelope"].(map[string]any)["n"]
			delete(m["envelope"].(map[string]any), "n")
		},
	} {
		var m map[string]any
		json.Unmarshal(raw, &m)
		change(m)
		b, _ := json.Marshal(m)
		if _, e := ParsePayload(b); e == nil {
			t.Fatal("invalid payload schema accepted")
		}
	}
	manifest, _ := b64.DecodeString(p.Manifest)
	var m map[string]any
	json.Unmarshal(manifest, &m)
	delete(m["files"].([]any)[0].(map[string]any), "size")
	b, _ := json.Marshal(m)
	if _, e := decodeManifest(b); e == nil {
		t.Fatal("missing size accepted")
	}
}

func TestRealExecutableAndLowOrderPublicKey(t *testing.T) {
	p, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	s, e := inspect("protect", "protect", p)
	if e != nil || s.file.Architecture != runtime.GOARCH {
		t.Fatal("real test ELF", e)
	}
	payload, _, _ := fixture(t, 0)
	raw, _ := b64.DecodeString(payload.Manifest)
	var m Manifest
	json.Unmarshal(raw, &m)
	if _, _, e = NewPayload(payload, m, make([]byte, 32)); e == nil {
		t.Fatal("low-order recipient accepted")
	}
	payload.Envelope.E = b64.EncodeToString(make([]byte, 32))
	if _, e = Unlock(payload, bytes.Repeat([]byte{0x23}, 32)); e == nil {
		t.Fatal("low-order ephemeral accepted")
	}
	if !hasNative(map[string]any{"targets": map[string]any{"x": map[string]any{"native": map[string]any{}}}}) {
		t.Fatal("native deps")
	}
	var obj map[string]any
	if strictJSON([]byte(`{"targets":{"n\u0061tive":{}}}`), &obj) != nil || !hasNative(obj) {
		t.Fatal("escaped native deps")
	}
}

func TestJSONUnicodeEscapes(t *testing.T) {
	for _, raw := range []string{`{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":"\ud800\u0041"}`} {
		var m map[string]any
		if strictJSON([]byte(raw), &m) == nil {
			t.Fatal("isolated surrogate accepted")
		}
	}
	for _, raw := range []string{`{"x":"\ud83d\ude00"}`, `{"x":"\\ud800"}`, `{"x":"有效 UTF-8"}`} {
		var m map[string]any
		if strictJSON([]byte(raw), &m) != nil {
			t.Fatal("valid Unicode rejected")
		}
	}
}

func TestProtectRollbackAndArchitecture(t *testing.T) {
	old := stubForArch
	defer func() { stubForArch = old }()
	for _, arch := range []struct {
		name    string
		machine uint16
	}{{"amd64", 62}, {"arm64", 183}} {
		for _, stage := range []string{"success", "missing-launcher", "replace", "sync"} {
			t.Run(arch.name+"/"+stage, func(t *testing.T) {
				stubForArch = func(name string) ([]byte, error) {
					if name != arch.name {
						t.Fatal("wrong launcher", name)
					}
					if stage == "missing-launcher" {
						return nil, errors.New("missing")
					}
					return elfBytes(arch.machine), nil
				}
				root := t.TempDir()
				path := filepath.Join(root, "app")
				original := elfBytes(arch.machine)
				for i := 0; i < 8; i++ {
					original = append(original, watermarkPlaceholder(i)...)
				}
				binary.LittleEndian.PutUint64(original[96:], uint64(len(original)))
				binary.LittleEndian.PutUint64(original[104:], uint64(len(original)))
				put(t, path, original)
				src, e := inspect("protect", "protect", path)
				if e != nil {
					t.Fatal(e)
				}
				src.file.Path = cipherName(0)
				base, _, priv := fixture(t, 0)
				public, _ := ecdhPrivate(priv)
				sources, e := prepareNativeWatermark(src, public)
				if e != nil {
					t.Fatal(e)
				}
				manifest := Manifest{}
				for _, source := range sources {
					manifest.Files = append(manifest.Files, source.file)
				}
				p, key, e := NewPayload(base, manifest, public)
				if e != nil {
					t.Fatal(e)
				}
				dest := filepath.Join(root, "out")
				replaced := false
				fs := publicationFS{rename: func(a, b string) error {
					if strings.Contains(filepath.Base(a), ".authgo-protected-") {
						if stage == "replace" {
							return errors.New("replace")
						}
						replaced = true
					}
					return os.Rename(a, b)
				}, remove: os.Remove, sync: func(p string) error {
					if replaced && stage == "sync" {
						replaced = false
						return errors.New("sync")
					}
					return syncDir(p)
				}}
				e = publishUsing(dest, sources, p, key, fs)
				got, _ := os.ReadFile(path)
				if stage == "success" {
					if e != nil || bytes.Equal(got, original) || len(got) < len(original)+64 {
						t.Fatal("replacement", e)
					}
					return
				}
				if e == nil || !bytes.Equal(got, original) {
					t.Fatal("original not preserved", e)
				}
				if _, e = os.Stat(dest); !os.IsNotExist(e) {
					t.Fatal("partial out")
				}
				files, _ := filepath.Glob(filepath.Join(root, ".authgo-*"))
				if len(files) != 0 {
					t.Fatal("temporary residue", files)
				}
			})
		}
	}
}
