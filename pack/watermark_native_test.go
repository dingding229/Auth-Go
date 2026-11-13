package pack

import (
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

func nativeWatermarkFixture(t *testing.T) (string, []byte, []int64) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "app")
	data := make([]byte, ChunkSize+2048)
	copy(data, elfBytes(62))
	positions := []int64{}
	for i := 0; i < 8; i++ {
		at := ChunkSize - 40 + i*128
		copy(data[at:], watermarkPlaceholder(i))
		positions = append(positions, int64(at))
	}
	binary.LittleEndian.PutUint64(data[96:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[104:], uint64(len(data)))
	if e := os.WriteFile(file, data, 0755); e != nil {
		t.Fatal(e)
	}
	return file, data, positions
}
func TestNativeWatermarkV2PrivateEncryptedIndex(t *testing.T) {
	file, original, positions := nativeWatermarkFixture(t)
	private := bytes.Repeat([]byte{0x23}, 32)
	recipient, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	input, e := inspect("protect", "protect", file)
	if e != nil {
		t.Fatal(e)
	}
	sources, e := prepareNativeWatermark(input, recipient.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	if len(sources) != 2 || sources[1].file.Name != watermarkIndexName || sources[1].file.Kind != "watermark" {
		t.Fatal("missing private index")
	}
	reader, e := sources[0].reader()
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := io.ReadAll(reader)
	reader.Close()
	if e != nil {
		t.Fatal(e)
	}
	tag, e := watermarkPublicTag(recipient.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	slot := []byte(tag + strings.Repeat("0", 64))
	if bytes.Count(prepared, slot) != 8 {
		t.Fatal("native slots not distinct/preserved")
	}
	for i, at := range positions {
		if !bytes.Equal(prepared[at:at+96], slot) {
			t.Fatal("cross-chunk slot", i)
		}
	}
	after, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(after, original) {
		t.Fatal("preparation wrote plaintext input", e)
	}
	var index watermarkIndex
	if e = json.Unmarshal(sources[1].generated, &index); e != nil {
		t.Fatal(e)
	}
	if index.V != "1" || index.Tag != tag || len(index.Files) != 1 || index.Files[0].Index != "0" || len(index.Files[0].Entries) != 1 || index.Files[0].Entries[0].Path == nil || len(index.Files[0].Entries[0].Path) != 0 {
		t.Fatal("private index schema")
	}
	for i, offset := range index.Files[0].Entries[0].Offsets {
		if offset != strconv.FormatInt(positions[i], 10) {
			t.Fatal("index offset precision/order")
		}
	}
	manifest := Manifest{}
	for _, s := range sources {
		manifest.Files = append(manifest.Files, s.file)
	}
	p, key, e := NewPayload(Payload{V: 2, AppKey: "app_test", Version: "1.0.0", BuiltAt: "2026-11-07T00:00:00Z", KeyID: "key-1", Config: testConfig()}, manifest, recipient.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	public, _ := b64.DecodeString(p.Manifest)
	for _, word := range []string{"\"offsets\"", "\"entries\"", "\"tag\"", tag} {
		if bytes.Contains(public, []byte(word)) {
			t.Fatal("private index exposed in public manifest")
		}
	}
	opened, e := Unlock(p, private)
	if e != nil || !bytes.Equal(opened, key) {
		t.Fatal("v2 envelope authentication", e)
	}
	clear(opened)
	encrypted := seal(t, p, key, 1, sources[1].generated)
	if bytes.Contains(encrypted, []byte(tag)) {
		t.Fatal("index not encrypted")
	}
	decoded, e := ReadChunk(bytes.NewReader(encrypted), int64(len(encrypted)), p, key, 1, 0)
	if e != nil || !bytes.Equal(decoded, sources[1].generated) {
		t.Fatal("encrypted index binding", e)
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, e = ReadChunk(bytes.NewReader(encrypted), int64(len(encrypted)), p, key, 1, 0); e == nil {
		t.Fatal("index tamper accepted")
	}

}
func TestNativeWatermarkMissingUnmappedAndChangedInputsReject(t *testing.T) {
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	pub := private.PublicKey().Bytes()
	for _, mode := range []string{"missing", "unmapped", "one-removed"} {
		t.Run(mode, func(t *testing.T) {
			file, original, _ := nativeWatermarkFixture(t)
			if mode == "missing" {
				original = elfBytes(62)
			} else if mode == "unmapped" {
				binary.LittleEndian.PutUint64(original[96:], 120)
				binary.LittleEndian.PutUint64(original[104:], 120)
			} else {
				original[ChunkSize-40+7*128] = 'X'
			}
			if e := os.WriteFile(file, original, 0755); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(t.TempDir(), "payload")
			e := ProtectWatermarked(file, target, Payload{AppKey: "app_test", Version: "1.0.0", BuiltAt: "2026-11-07T00:00:00Z", KeyID: "key-1", Config: testConfig()}, pub)
			if e == nil {
				t.Fatal("missing/unmapped SDK slots accepted")
			}
			after, e := os.ReadFile(file)
			if e != nil || !bytes.Equal(after, original) {
				t.Fatal("input changed on refusal", e)
			}
			if _, e = os.Stat(target); !os.IsNotExist(e) {
				t.Fatal("output published on refusal")
			}
		})
	}
	expected := watermarkPlaceholder(0)
	replacement := []byte(strings.Repeat("a", 32) + strings.Repeat("0", 64))
	for _, size := range []int{1, 7, 31, 95, 96, 97, 113} {
		raw := append([]byte("prefix"), expected...)
		raw = append(raw, []byte("suffix")...)
		reader := watermarkPatchReader{ReadCloser: io.NopCloser(bytes.NewReader(raw)), patches: []watermarkBytePatch{{6, expected, replacement}}}
		var out bytes.Buffer
		buffer := make([]byte, size)
		for {
			n, e := reader.Read(buffer)
			out.Write(buffer[:n])
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		want := append([]byte("prefix"), replacement...)
		want = append(want, []byte("suffix")...)
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatal("patch reader boundary", size)
		}
	}
	bad := append([]byte(nil), expected...)
	bad[33] = 'X'
	reader := watermarkPatchReader{ReadCloser: io.NopCloser(bytes.NewReader(bad)), patches: []watermarkBytePatch{{0, expected, replacement}}}
	if _, e := io.ReadAll(&reader); e == nil {
		t.Fatal("changed source bytes overwritten silently")
	}
}
func TestV2ManifestRequiresOneEncryptedIndexAndCode(t *testing.T) {
	files := []File{{Name: "protect", Kind: "protect", Path: cipherName(0), Size: 120, ChunkSize: ChunkSize, Encoding: "raw", Architecture: "amd64"}, {Name: watermarkIndexName, Kind: "watermark", Path: cipherName(1), Size: 200, ChunkSize: ChunkSize, Encoding: "raw"}}
	raw, _ := json.Marshal(Manifest{files})
	if _, e := decodeManifestVersion(raw, 2); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func([]File) []File{
		func(f []File) []File { return f[:1] }, func(f []File) []File { f[1].Name = "wrong"; return f }, func(f []File) []File { f[1].Encoding = "tar"; return f }, func(f []File) []File { f[1].Size = 0; return f }, func(f []File) []File { f[1].Size = watermarkIndexMax + 1; return f }, func(f []File) []File { f[1].Architecture = "amd64"; return f }, func(f []File) []File { f = f[1:]; f[0].Path = cipherName(0); return f },
	} {
		copyFiles := append([]File(nil), files...)
		raw, _ := json.Marshal(Manifest{mutate(copyFiles)})
		if _, e := decodeManifestVersion(raw, 2); e == nil {
			t.Fatal("malformed v2 index accepted")
		}
	}
}
