package pack

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
)

const watermarkIndexName = "__authgo_watermark"
const watermarkIndexMax = 8 << 20

// Private offsets are decimal strings, never lossy JSON floating point values.
type watermarkIndex struct {
	V     string               `json:"v"`
	Tag   string               `json:"tag"`
	Files []watermarkIndexFile `json:"files"`
}
type watermarkIndexFile struct {
	Index   string                `json:"index"`
	Entries []watermarkIndexEntry `json:"entries"`
}
type watermarkIndexEntry struct {
	Path    []string `json:"path"`
	Offsets []string `json:"offsets"`
}
type watermarkBytePatch struct {
	offset                int64
	expected, replacement []byte
}
type watermarkPatchReader struct {
	io.ReadCloser
	patches  []watermarkBytePatch
	position int64
}

func (r *watermarkPatchReader) Read(buffer []byte) (int, error) {
	n, e := r.ReadCloser.Read(buffer)
	end := r.position + int64(n)
	for _, patch := range r.patches {
		last := patch.offset + int64(len(patch.expected))
		if last <= r.position {
			continue
		}
		if patch.offset >= end {
			break
		}
		start, finish := patch.offset, last
		if start < r.position {
			start = r.position
		}
		if finish > end {
			finish = end
		}
		a, b := start-r.position, finish-r.position
		from, to := start-patch.offset, finish-patch.offset
		if !bytes.Equal(buffer[a:b], patch.expected[from:to]) {
			return 0, errors.New("watermark source changed")
		}
		copy(buffer[a:b], patch.replacement[from:to])
	}
	r.position = end
	return n, e
}
func watermarkPublicTag(public []byte) (string, error) {
	if len(public) != 32 {
		return "", invalid
	}
	tag, e := hkdf.Key(sha256.New, public, nil, "authgo/watermark/tag/v1", 16)
	if e != nil {
		return "", invalid
	}
	defer clear(tag)
	return hex.EncodeToString(tag), nil
}

// Variable-length independent random labels spread slot byte offsets inside the
// language's safe constant container. Original bytecode/constant references and
// JS Directive Prologues are not moved or rewritten to manufacture positions.
// The distinct index prefix also prevents deduplication of equal tag/value pairs.
func watermarkSlotLabel(random []byte, index int) string {
	length := 8 + int(random[24+index])%17
	return "wm" + strconv.Itoa(index) + ":" + hex.EncodeToString(random[:length]) + ":"
}

func watermarkPlaceholder(index int) []byte {
	return []byte(fmt.Sprintf("c0dec0dec0dec0de%016x%s", index, "0000000000000000000000000000000000000000000000000000000000000000"))
}
func prepareNativeWatermark(input source, public []byte) ([]source, error) {
	if input.file.Kind != "protect" || input.file.Encoding != "raw" {
		return nil, errors.New("native watermark requires protected ELF")
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return nil, e
	}
	file, e := openSafe(input.path)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	stat, e := file.Stat()
	if e != nil || !os.SameFile(input.info, stat) || stat.Size() != input.info.Size() || !stat.ModTime().Equal(input.info.ModTime()) {
		return nil, errors.New("input changed")
	}
	image, e := elf.NewFile(file)
	if e != nil {
		return nil, errors.New("invalid native watermark ELF")
	}
	defer image.Close()
	isLoaded := func(offset int64) bool {
		for _, segment := range image.Progs {
			if segment.Type != elf.PT_LOAD || segment.Off > uint64(stat.Size()) || segment.Filesz > uint64(stat.Size())-segment.Off {
				continue
			}
			if uint64(offset) >= segment.Off && uint64(offset)-segment.Off <= segment.Filesz && 96 <= segment.Filesz-(uint64(offset)-segment.Off) {
				return true
			}
		}
		return false
	}
	placeholders := make([][]byte, 8)
	counts := make([]int, 8)
	for i := range placeholders {
		placeholders[i] = watermarkPlaceholder(i)
	}
	replacement := []byte(tag + "0000000000000000000000000000000000000000000000000000000000000000")
	buffer := make([]byte, 1<<20)
	carry := []byte{}
	var position, next int64
	patches := []watermarkBytePatch{}
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			data := append(carry, buffer[:n]...)
			start := position - int64(len(carry))
			for i := 0; i+96 <= len(data); i++ {
				at := start + int64(i)
				if at < next || data[i] != 'c' || !isLoaded(at) {
					continue
				}
				for p, placeholder := range placeholders {
					if bytes.Equal(data[i:i+96], placeholder) {
						patches = append(patches, watermarkBytePatch{at, placeholder, replacement})
						counts[p]++
						if len(patches) > 65535 {
							return nil, errors.New("too many watermark slots")
						}
						break
					}
				}
			}
			position += int64(n)
			if position >= 95 {
				next = position - 95
			}
			left := len(data) - 95
			if left < 0 {
				left = 0
			}
			carry = append([]byte(nil), data[left:]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("watermark source read failed")
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	for _, count := range counts {
		if count < 1 {
			return nil, errors.New("missing native watermark slots: rebuild with the current Guard SDK; trimming or removing SDK references is unsupported")
		}
	}
	sort.Slice(patches, func(i, j int) bool { return patches[i].offset < patches[j].offset })
	offsets := make([]string, len(patches))
	for i, p := range patches {
		if i > 0 && patches[i-1].offset+96 > p.offset {
			return nil, errors.New("overlapping native watermark slots")
		}
		offsets[i] = strconv.FormatInt(p.offset, 10)
	}
	index := watermarkIndex{V: "1", Tag: tag, Files: []watermarkIndexFile{{Index: "0", Entries: []watermarkIndexEntry{{Path: []string{}, Offsets: offsets}}}}}
	raw, e := json.Marshal(index)
	if e != nil || len(raw) > watermarkIndexMax {
		return nil, errors.New("watermark index too large")
	}
	input.patches = patches
	input.file.Path = cipherName(0)
	metadata := source{file: File{Name: watermarkIndexName, Kind: "watermark", Encoding: "raw", Size: int64(len(raw)), ChunkSize: ChunkSize, Path: cipherName(1)}, generated: raw}
	return []source{input, metadata}, nil
}

// ProtectWatermarked creates the native v2 format. It is also used by the
// integration harness; The CLI uses the same v2 emission rules.
// Trust configuration is supplied at build time, exactly as for NewPayload.
func ProtectWatermarked(input, destination string, p Payload, public []byte) error {
	source, e := inspect("protect", "protect", input)
	if e != nil {
		return e
	}
	sources, e := prepareNativeWatermark(source, public)
	if e != nil {
		return e
	}
	manifest := Manifest{}
	for _, source := range sources {
		manifest.Files = append(manifest.Files, source.file)
	}
	p.V = 2
	p, key, e := NewPayload(p, manifest, public)
	if e != nil {
		return e
	}
	defer clear(key)
	return publish(destination, sources, p, key)
}
