package pack

import (
	"archive/tar"
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Deliberately hand-encoded, including global refs and co_consts TYPE_REF.
// Real compiler/SDK runtime behavior is exercised by scripts/test-watermark-e2e.py.
type pythonMarshalFixture struct {
	data []byte
	refs map[string]uint32
}

func (f *pythonMarshalFixture) integer(n uint32) {
	f.data = binary.LittleEndian.AppendUint32(f.data, n)
}
func (f *pythonMarshalFixture) define(kind byte, name string) {
	if name != "" {
		f.refs[name] = uint32(len(f.refs))
		kind |= 128
	}
	f.data = append(f.data, kind)
}
func (f *pythonMarshalFixture) ref(name string) {
	f.data = append(f.data, 'r')
	f.integer(f.refs[name])
}
func (f *pythonMarshalFixture) text(s, name string) {
	f.define('z', name)
	f.data = append(f.data, byte(len(s)))
	f.data = append(f.data, s...)
}
func (f *pythonMarshalFixture) blob(s string) {
	f.define('s', "")
	f.integer(uint32(len(s)))
	f.data = append(f.data, s...)
}
func (f *pythonMarshalFixture) code(version int, name string, constants func()) {
	f.define('c', name)
	fields := 6
	if version >= 311 {
		fields = 5
	}
	for i := 0; i < fields; i++ {
		f.integer(0)
	}
	f.blob("\x64\x00\x53\x00")
	constants()
	f.ref("aliases")
	if version < 311 {
		f.ref("aliases")
		f.ref("aliases")
		f.ref("aliases")
	} else {
		f.ref("aliases")
		f.blob("\x20")
	}
	f.text("fixture.py", "")
	f.text(name, "")
	if version >= 311 {
		f.text(name, "")
	}
	f.integer(1)
	f.blob("")
	if version >= 311 {
		f.blob("")
	}
}
func pythonGraphFixture(version int, magic uint16, empty bool) []byte {
	f := pythonMarshalFixture{data: make([]byte, 16), refs: map[string]uint32{}}
	binary.LittleEndian.PutUint16(f.data, magic)
	f.data[2], f.data[3] = 13, 10
	f.code(version, "root", func() {
		if empty {
			f.define(')', "aliases")
			f.data = append(f.data, 0)
			return
		}
		f.define(')', "root-constants")
		f.data = append(f.data, 3)
		f.code(version, "child", func() {
			f.define(')', "aliases")
			f.data = append(f.data, 1)
			f.text("name", "shared-string")
		})
		f.ref("child") // shared code object, not a second definition
		f.code(version, "second", func() { f.ref("aliases") })
	})
	return f.data
}
func pythonTestFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	name := filepath.Join(t.TempDir(), "__init__.pyc")
	if e := os.WriteFile(name, data, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(name)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func pythonParseFixture(t *testing.T, data []byte, version int) *watermarkMarshalValue {
	t.Helper()
	f := pythonTestFile(t, data)
	r := watermarkMarshal{window: watermarkWindow{file: f, size: int64(len(data))}, version: version, pos: 16}
	root := r.object(false)
	if r.pos != int64(len(data)) {
		t.Fatal("marshal tail")
	}
	return root.value
}
func pythonConstantStrings(t *testing.T, data []byte, tuple *watermarkMarshalValue, prefix int) {
	t.Helper()
	sentinel := 0
	if prefix == 0 {
		sentinel = 1
		if len(tuple.children) == 0 || tuple.children[0].value.kind != 'N' {
			t.Fatal("empty constants changed function docstring")
		}
	}
	if tuple.n != int64(prefix+8+sentinel) {
		t.Fatalf("constant count %d, original prefix %d", tuple.n, prefix)
	}
	seen := map[string]bool{}
	for _, edge := range tuple.children[prefix+sentinel:] {
		v := edge.value
		if v.kind != 'z' {
			t.Fatal("slot is not a direct string constant")
		}
		s := string(data[v.start+2 : v.end])
		if seen[s] || !strings.Contains(s, strings.Repeat("a", 32)+strings.Repeat("0", 64)) {
			t.Fatal("non-distinct slot or bad contents")
		}
		seen[s] = true
	}
}
func TestPythonWatermarkEveryCodeAndGlobalAliases(t *testing.T) {
	for i, magic := range []uint16{3413, 3425, 3439, 3495, 3531, 3571, 3627} {
		version := 308 + i
		for _, empty := range []bool{false, true} {
			t.Run(strconv.Itoa(version)+"-empty="+strconv.FormatBool(empty), func(t *testing.T) {
				original := pythonGraphFixture(version, magic, empty)
				f := pythonTestFile(t, original)
				edits, offsets, size, e := preparePythonEntry(f, int64(len(original)), strings.Repeat("a", 32))
				if e != nil {
					t.Fatal(e)
				}
				r, e := watermarkEditedReader(f, int64(len(original)), edits)
				if e != nil {
					t.Fatal(e)
				}
				data, e := io.ReadAll(r)
				if e != nil || size != int64(len(data)) || !bytes.Equal(original[:16], data[:16]) {
					t.Fatal("rewrite size/header", e)
				}
				count := 16 // root plus two distinct child codes sharing co_consts
				if empty {
					count = 8
				}
				if len(offsets) != count {
					t.Fatalf("slots %d want %d", len(offsets), count)
				}
				last := -1
				for _, offset := range offsets {
					at, e := strconv.Atoi(offset)
					if e != nil || at <= last || at+96 > len(data) || string(data[at:at+96]) != strings.Repeat("a", 32)+strings.Repeat("0", 64) {
						t.Fatal("bad or unsorted private offset", e)
					}
					last = at
				}
				root := pythonParseFixture(t, data, version)
				before := pythonParseFixture(t, original, version)
				checkCodeBytes := func(old, actual *watermarkMarshalValue) {
					t.Helper()
					a, b := old.children[0].value, actual.children[0].value
					if !bytes.Equal(original[old.start+1:old.children[0].start], data[actual.start+1:actual.children[0].start]) || !bytes.Equal(original[a.start+5:a.end], data[b.start+5:b.end]) {
						t.Fatal("original code integers/co_code changed")
					}
				}
				checkCodeBytes(before, root)
				constants := root.children[1].value
				if empty {
					pythonConstantStrings(t, data, constants, 0)
					for _, edge := range root.children[2:4] {
						if edge.value.n != 0 || edge.value == constants {
							t.Fatal("expanded empty constants leaked into names/locals")
						}
					}
				} else {
					pythonConstantStrings(t, data, constants, 3)
					child := constants.children[0].value
					second := constants.children[2].value
					checkCodeBytes(before.children[1].value.children[0].value, child)
					checkCodeBytes(before.children[1].value.children[2].value, second)
					if child != constants.children[1].value || child == second || child.children[1].value != second.children[1].value {
						t.Fatal("shared code or shared code constants identity lost")
					}
					pythonConstantStrings(t, data, child.children[1].value, 1)
					aliases := child.children[2].value
					if aliases.n != 1 || aliases == child.children[1].value || aliases != root.children[2].value || aliases != second.children[2].value || aliases != child.children[3].value {
						t.Fatal("ordinary tuple aliases lost/enlarged")
					}
					if aliases.children[0].value != child.children[1].value.children[0].value {
						t.Fatal("shared original constant identity lost")
					}
				}
				after, e := os.ReadFile(f.Name())
				if e != nil || !bytes.Equal(after, original) {
					t.Fatal("preparation changed input", e)
				}
			})
		}
	}
}

func TestPythonWatermarkCreateV2AndEncryptedIndex(t *testing.T) {
	original := pythonGraphFixture(311, 3495, false)
	file := pythonTestFile(t, original)
	private, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x23}, 32))
	if e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(t.TempDir(), "payload")
	p := Payload{AppKey: "app_test", Version: "1.0.0", BuiltAt: "2026-11-09T00:00:00Z", KeyID: "key-test", Config: testConfig()}
	if e = CreateWatermarkedPython(filepath.Dir(file.Name()), destination, p, private.PublicKey().Bytes()); e != nil {
		t.Fatal(e)
	}
	if e = Verify(destination); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(destination, "payload.json"))
	if e != nil {
		t.Fatal(e)
	}
	p, e = ParsePayload(raw)
	if e != nil || p.V != 2 {
		t.Fatal("production v2", e)
	}
	key, e := Unlock(p, private.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	decrypt := func(index uint32) []byte {
		t.Helper()
		ciphertext, e := os.ReadFile(filepath.Join(destination, cipherName(int(index))))
		if e != nil {
			t.Fatal(e)
		}
		plain, e := ReadChunk(bytes.NewReader(ciphertext), int64(len(ciphertext)), p, key, index, 0)
		if e != nil {
			t.Fatal(e)
		}
		return plain
	}
	var index watermarkIndex
	if e = json.Unmarshal(decrypt(1), &index); e != nil {
		t.Fatal(e)
	}
	if len(index.Files) != 1 || len(index.Files[0].Entries) != 1 || len(index.Files[0].Entries[0].Offsets) != 16 {
		t.Fatal("nested production private index")
	}
	archive := tar.NewReader(bytes.NewReader(decrypt(0)))
	header, e := archive.Next()
	if e != nil || header.Name != "__init__.pyc" {
		t.Fatal("production pyc archive", e)
	}
	data, e := io.ReadAll(archive)
	if e != nil {
		t.Fatal(e)
	}
	for _, text := range index.Files[0].Entries[0].Offsets {
		at, e := strconv.Atoi(text)
		if e != nil || at+96 > len(data) || string(data[at:at+96]) != index.Tag+strings.Repeat("0", 64) {
			t.Fatal("production offset", e)
		}
	}
	if _, e = archive.Next(); e != io.EOF {
		t.Fatal("unexpected plaintext archive entry", e)
	}
	items, e := os.ReadDir(destination)
	if e != nil || len(items) != 3 {
		t.Fatal("plaintext persisted outside encrypted files", e)
	}
}

func TestPythonWatermarkRejectsUnsafeMarshal(t *testing.T) {
	good := pythonGraphFixture(311, 3495, false)
	badRef := append([]byte(nil), good...)
	// root TYPE_CODE is not available until complete: a ref to it as co_code
	// must fail, not accidentally resolve to a later global reference.
	badRef = append(badRef[:37], append([]byte{'r', 0, 0, 0, 0}, badRef[46:]...)...)
	cases := map[string][]byte{
		"truncated": good[:len(good)-1],
		"tail":      append(append([]byte(nil), good...), 'N'),
		"bad-ref":   badRef,
	}
	// A recursive constants tuple cannot be split from its ordinary aliases
	// while retaining the original self-identity. Report that exact boundary.
	f := pythonMarshalFixture{data: append([]byte(nil), good[:16]...), refs: map[string]uint32{}}
	f.code(311, "root", func() {
		f.define(')', "aliases")
		f.data = append(f.data, 1)
		f.ref("aliases")
	})
	cases["recursive-constants"] = f.data
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			f := pythonTestFile(t, data)
			edits, offsets, size, e := preparePythonEntry(f, int64(len(data)), strings.Repeat("a", 32))
			if e == nil || len(edits) != 0 || len(offsets) != 0 || size != 0 {
				t.Fatal("unsafe marshal silently accepted", e)
			}
			if name == "recursive-constants" && !strings.Contains(e.Error(), "recursive Python co_consts alias") {
				t.Fatal("missing concrete rejection reason", e)
			}
			private, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x23}, 32))
			if e != nil {
				t.Fatal(e)
			}
			destination := filepath.Join(t.TempDir(), "must-not-publish")
			p := Payload{AppKey: "app_test", Version: "1.0.0", BuiltAt: "2026-11-09T00:00:00Z", KeyID: "key-test", Config: testConfig()}
			if e = CreateWatermarkedPython(filepath.Dir(f.Name()), destination, p, private.PublicKey().Bytes()); e == nil {
				t.Fatal("unsafe production input published without a watermark")
			}
			if _, e = os.Stat(destination); !os.IsNotExist(e) {
				t.Fatal("output persisted on refusal", e)
			}
			after, e := os.ReadFile(f.Name())
			if e != nil || !bytes.Equal(after, data) {
				t.Fatal("refusal changed source", e)
			}
		})
	}
}
