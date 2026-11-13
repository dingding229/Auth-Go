package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

// In-memory random-access destination makes it observable whether a rewrite
// happened before ALL chunks/slots were validated. No executable is launched.
type payloadV2Memory struct {
	bytes    []byte
	rewrites int
}

func (m *payloadV2Memory) Write(b []byte) (int, error) {
	m.bytes = append(m.bytes, b...)
	return len(b), nil
}
func (m *payloadV2Memory) ReadAt(b []byte, at int64) (int, error) {
	if at < 0 || at > int64(len(m.bytes)) {
		return 0, io.EOF
	}
	n := copy(b, m.bytes[at:])
	if n != len(b) {
		return n, io.EOF
	}
	return n, nil
}
func (m *payloadV2Memory) WriteAt(b []byte, at int64) (int, error) {
	m.rewrites++
	if at < 0 || at > int64(len(m.bytes)) || int64(len(b)) > int64(len(m.bytes))-at {
		return 0, io.ErrShortWrite
	}
	return copy(m.bytes[at:], b), nil
}
func payloadV2PlainSlots() []byte {
	return bytes.Repeat([]byte(payloadV2Tag+strings.Repeat("0", 64)), 8)
}
func payloadV2ProtectedFixture(t *testing.T, plain, private []byte, metaFirst bool) ([]byte, []byte) {
	t.Helper()
	p, key, _ := payloadVector(t)
	p = payloadV2Fixture(t, p)
	files, _ := p.Files()
	files[0].Size = int64(len(plain))
	files[1].Size = int64(len(private))
	if metaFirst {
		files[0], files[1] = files[1], files[0]
		files[0].Path, files[1].Path = "00000000.agc", "00000001.agc"
	}
	manifest, _ := json.Marshal(PayloadManifest{Files: files})
	p.Manifest = payloadB64.EncodeToString(manifest)
	bind, e := p.PayloadBinding()
	if e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	var encrypted []byte
	for i, f := range files {
		content := plain
		if f.Kind == "watermark" {
			content = private
		}
		count := max(1, (len(content)+PayloadChunkSize-1)/PayloadChunkSize)
		for j := 0; j < count; j++ {
			begin, end := j*PayloadChunkSize, min(len(content), (j+1)*PayloadChunkSize)
			nonce := binary.BigEndian.AppendUint32(nil, uint32(i))
			nonce = binary.BigEndian.AppendUint64(nonce, uint64(j))
			aad := append([]byte("authgo-payload-chunk-v1\x00"), bind...)
			aad = binary.BigEndian.AppendUint32(aad, uint32(i))
			aad = binary.BigEndian.AppendUint64(aad, uint64(j))
			last := byte(0)
			if j == count-1 {
				last = 1
			}
			aad = append(aad, last)
			encrypted = g.Seal(encrypted, nonce, content[begin:end], aad)
		}
	}
	metadata, _ := json.Marshal(p)
	out := append(make([]byte, 64), metadata...)
	out = append(out, encrypted...)
	footer := append([]byte(nil), protectedMagic[:]...)
	footer = binary.BigEndian.AppendUint32(footer, 1)
	footer = binary.BigEndian.AppendUint32(footer, 0)
	for _, n := range []uint64{64, uint64(len(metadata)), uint64(len(encrypted))} {
		footer = binary.BigEndian.AppendUint64(footer, n)
	}
	footer = append(footer, make([]byte, 16)...)
	material := append(append([]byte(nil), key...), bytes.Repeat([]byte{0x2a}, 32)...)
	return append(out, footer...), material
}
func TestPayloadV2ProtectedAuthenticatesMetadataAndWholeTargetBeforeRewrite(t *testing.T) {
	for _, metaFirst := range []bool{false, true} {
		// Put one slot across a code chunk boundary and the final slot in the
		// final chunk. Metadata itself also spans multiple authenticated chunks.
		start := PayloadChunkSize - 48
		plain := append(bytes.Repeat([]byte{'x'}, start), payloadV2PlainSlots()...)
		offsets := make([]string, 8)
		for i := range offsets {
			offsets[i] = strconv.Itoa(start + i*payloadSlotSize)
		}
		private := payloadV2Index(t, offsets)
		if metaFirst {
			private = bytes.Replace(private, []byte(`"index":"0"`), []byte(`"index":"1"`), 1)
		}
		private = append(bytes.Repeat([]byte{' '}, PayloadChunkSize), private...)
		raw, material := payloadV2ProtectedFixture(t, plain, private, metaFirst)
		image, e := ReadProtectedImage(bytes.NewReader(raw), int64(len(raw)))
		if e != nil {
			t.Fatal(e)
		}
		var target payloadV2Memory
		if e = image.Decrypt(&target, material); e != nil {
			t.Fatal("v2 protected", e)
		}
		if len(target.bytes) != len(plain) || target.rewrites != 8 {
			t.Fatal("length/slots")
		}
		want := append([]byte(nil), plain...)
		for i := 0; i < 8; i++ {
			copy(want[start+i*payloadSlotSize+32:], hex.EncodeToString(material[32:]))
		}
		if !bytes.Equal(target.bytes, want) {
			t.Fatal("watermark mismatch")
		}
		for _, stream := range []string{"code", "metadata"} {
			bad := append([]byte(nil), raw...)
			at := image.Start + image.Length - 1
			if stream == "metadata" {
				if metaFirst {
					at = image.Start - 1
				} else {
					at = int64(len(raw) - ProtectedFooterSize - 1)
				}
			}
			bad[at] ^= 1
			changed, e := ReadProtectedImage(bytes.NewReader(bad), int64(len(bad)))
			if e != nil {
				t.Fatal(e)
			}
			var output payloadV2Memory
			if e = changed.Decrypt(&output, material); e == nil || output.rewrites != 0 {
				t.Fatal("unauthenticated rewrite", stream, e)
			}
			if stream == "metadata" && len(output.bytes) != 0 {
				t.Fatal("code decrypted before all metadata authenticated")
			}
		}
		clear(material)
	}
}
func TestPayloadV2ProtectedRejectsEveryBadSlotBeforeAnyRewrite(t *testing.T) {
	for _, fault := range []string{"late-tag", "late-zero", "bound", "overlap", "zero-wm", "short-material", "extra-material", "extra-entry", "nested-entry", "malformed-index"} {
		t.Run(fault, func(t *testing.T) {
			plain, private := payloadV2PlainSlots(), payloadV2Index(t, nil)
			switch fault {
			case "late-tag":
				plain[7*payloadSlotSize] ^= 1
			case "late-zero":
				plain[7*payloadSlotSize+95] = '1'
			case "bound":
				private = bytes.Replace(private, []byte(`"672"`), []byte(`"673"`), 1)
			case "overlap":
				private = bytes.Replace(private, []byte(`"96"`), []byte(`"95"`), 1)
			case "extra-entry":
				var index payloadWatermarkIndex
				payloadJSON(private, &index)
				index.Files[0].Entries = append(index.Files[0].Entries, index.Files[0].Entries[0])
				private, _ = json.Marshal(index)
			case "nested-entry":
				private = bytes.Replace(private, []byte(`"path":[]`), []byte(`"path":["main"]`), 1)
			case "malformed-index":
				private = bytes.Replace(private, []byte(`"v":"1"`), []byte(`"v":"1","v":"1"`), 1)
			}
			raw, material := payloadV2ProtectedFixture(t, plain, private, false)
			switch fault {
			case "zero-wm":
				clear(material[32:])
			case "short-material":
				material = material[:32]
			case "extra-material":
				material = append(material, 1)
			}
			image, e := ReadProtectedImage(bytes.NewReader(raw), int64(len(raw)))
			if e != nil {
				t.Fatal(e)
			}
			var target payloadV2Memory
			if e = image.Decrypt(&target, material); e == nil || target.rewrites != 0 {
				t.Fatal("bad slots/material rewritten", e)
			}
			clear(material)
		})
	}
}
func TestPayloadV2WatermarkSlotsReferenced(t *testing.T) {
	seen := map[string]bool{}
	for i, s := range watermarkSlots {
		if len(s) != payloadSlotSize || s[:32] != fmt.Sprintf("c0dec0dec0dec0de%016x", i) || s[32:] != strings.Repeat("0", 64) || seen[s] {
			t.Fatal("invalid raw placeholder", i)
		}
		seen[s] = true
	}
	before := watermarkTouch.Load()
	touchWatermarkSlots()
	if watermarkTouch.Load() == before {
		t.Fatal("touch has no observable effect")
	}
}
