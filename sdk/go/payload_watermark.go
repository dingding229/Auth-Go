package sdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

const payloadSlotSize = 96
const payloadIndexLimit = 65535

// A fresh signed response with unusable watermark material is terminal, even
// for the launcher's separate proof-cache fallback. It is not a server refusal
// and must not erase otherwise valid licensing evidence.
type payloadWatermarkError struct{ cause error }

func (e *payloadWatermarkError) Error() string { return e.cause.Error() }
func (e *payloadWatermarkError) Unwrap() error { return e.cause }

func payloadNonzero(b []byte) bool {
	var all byte
	for _, v := range b {
		all |= v
	}
	return all != 0
}
func payloadLowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func payloadResponseWatermark(raw json.RawMessage) ([]byte, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil && payloadLowerHex(text, 64) {
		wm, e := hex.DecodeString(text)
		if e == nil && payloadNonzero(wm) {
			return wm, nil
		}
		clear(wm)
	}
	return nil, &payloadWatermarkError{failure(ResponseInvalid, "内容水印响应无效", nil)}
}

// Keep the private wire schema separate from public manifests. Decimal strings
// are parsed only after exact-key/type/duplicate validation by payloadJSON.
// This parser can be reused by archive-aware loaders; this SDK only applies
// watermarks to the selected native raw protected file.
type payloadWatermarkIndex struct {
	V     string                 `json:"v"`
	Tag   string                 `json:"tag"`
	Files []payloadWatermarkFile `json:"files"`
}
type payloadWatermarkFile struct {
	Index   string                  `json:"index"`
	Entries []payloadWatermarkEntry `json:"entries"`
}
type payloadWatermarkEntry struct {
	Path    []string `json:"path"`
	Offsets []string `json:"offsets"`
}

func payloadDecimal(s string, limit int64) (int64, error) {
	if s == "" || len(s) > 19 || len(s) > 1 && s[0] == '0' {
		return 0, payloadInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, payloadInvalid
		}
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n > limit {
		return 0, payloadInvalid
	}
	return n, nil
}
func payloadSafeEntry(s string) bool {
	if !utf8.ValidString(s) || s == "" || s == "." || strings.ContainsAny(s, "\\\x00:") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == ".." || strings.HasPrefix(s, "../") {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// Bound arrays before payloadJSON's canonical duplicate/type validation builds
// its value tree. Even an authenticated sender cannot make a small JSON stream
// allocate millions of file/entry/offset objects before count checks run.
func payloadWatermarkIndexCounts(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	counts := map[string]int{"files": 0, "entries": 0, "offsets": 0}
	var scan func(string, int) error
	scan = func(name string, depth int) error {
		if depth > 64 {
			return payloadInvalid
		}
		token, e := d.Token()
		if e != nil {
			return payloadInvalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return payloadInvalid
				}
				field, ok := key.(string)
				if !ok {
					return payloadInvalid
				}
				if e = scan(field, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return payloadInvalid
			}
		case '[':
			count := 0
			for d.More() {
				count++
				if name == "path" {
					if count > 8 {
						return payloadInvalid
					}
				} else if total, ok := counts[name]; ok {
					if total == payloadIndexLimit {
						return payloadInvalid
					}
					counts[name] = total + 1
				} else {
					return payloadInvalid
				}
				if e = scan("", depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return payloadInvalid
			}
		default:
			return payloadInvalid
		}
		return nil
	}
	if e := scan("", 0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return payloadInvalid
	}
	return nil
}
func parsePayloadWatermarkIndex(raw []byte, files []PayloadFile) (payloadWatermarkIndex, error) {
	var out payloadWatermarkIndex
	if len(raw) == 0 || len(raw) > payloadMaxManifest || payloadWatermarkIndexCounts(raw) != nil || payloadJSON(raw, &out) != nil || out.V != "1" || !payloadLowerHex(out.Tag, 32) || out.Files == nil || len(out.Files) == 0 || len(out.Files) > payloadIndexLimit || len(files) > payloadIndexLimit {
		return payloadWatermarkIndex{}, payloadInvalid
	}
	seen := make(map[int]bool)
	entries, offsets := 0, 0
	for _, file := range out.Files {
		index, e := payloadDecimal(file.Index, payloadIndexLimit-1)
		if e != nil || index >= int64(len(files)) || seen[int(index)] || files[index].Kind == "watermark" || file.Entries == nil || len(file.Entries) == 0 || len(file.Entries) > payloadIndexLimit-entries {
			return payloadWatermarkIndex{}, payloadInvalid
		}
		seen[int(index)] = true
		entries += len(file.Entries)
		f := files[index]
		paths := make(map[string]bool)
		count := 0
		for _, entry := range file.Entries {
			if entry.Path == nil || len(entry.Path) > 8 || entry.Offsets == nil || len(entry.Offsets) == 0 || len(entry.Offsets) > payloadIndexLimit-offsets {
				return payloadWatermarkIndex{}, payloadInvalid
			}
			for _, name := range entry.Path {
				if !payloadSafeEntry(name) {
					return payloadWatermarkIndex{}, payloadInvalid
				}
			}
			switch f.Kind {
			case "protect", "node":
				if len(entry.Path) != 0 {
					return payloadWatermarkIndex{}, payloadInvalid
				}
			case "python", "php":
				if len(entry.Path) != 1 {
					return payloadWatermarkIndex{}, payloadInvalid
				}
			case "java":
				if len(entry.Path) == 0 {
					return payloadWatermarkIndex{}, payloadInvalid
				}
			case "dotnet":
				if len(entry.Path) != 1 || strings.Contains(entry.Path[0], "/") || !strings.HasSuffix(strings.ToLower(entry.Path[0]), ".dll") {
					return payloadWatermarkIndex{}, payloadInvalid
				}
			default:
				return payloadWatermarkIndex{}, payloadInvalid
			}
			pathKey, _ := json.Marshal(entry.Path)
			if paths[string(pathKey)] {
				return payloadWatermarkIndex{}, payloadInvalid
			}
			paths[string(pathKey)] = true
			last := int64(-payloadSlotSize)
			for _, text := range entry.Offsets {
				n, e := payloadDecimal(text, math.MaxInt64/2)
				if e != nil || n < last+payloadSlotSize || (len(entry.Path) == 0 && (f.Size < payloadSlotSize || n > f.Size-payloadSlotSize)) {
					return payloadWatermarkIndex{}, payloadInvalid
				}
				last = n
			}
			count += len(entry.Offsets)
			offsets += len(entry.Offsets)
		}
		if count < 8 {
			return payloadWatermarkIndex{}, payloadInvalid
		}
	}
	for index, file := range files {
		if file.Kind != "watermark" && !seen[index] {
			return payloadWatermarkIndex{}, payloadInvalid
		}
	}
	return out, nil
}

type payloadWatermarkTarget interface {
	io.ReaderAt
	io.WriterAt
}

// Validate every slot against the authenticated tag and unmodified zero bytes
// before the first rewrite. Only the caller's anonymous memfd/tmpfs is modified.
func applyPayloadWatermark(target payloadWatermarkTarget, size int64, tag string, entry payloadWatermarkEntry, wm []byte) error {
	if len(wm) != 32 || !payloadNonzero(wm) || !payloadLowerHex(tag, 32) || entry.Path == nil || len(entry.Path) != 0 || len(entry.Offsets) < 8 || len(entry.Offsets) > payloadIndexLimit {
		return payloadInvalid
	}
	positions := make([]int64, len(entry.Offsets))
	var expected, actual [payloadSlotSize]byte
	copy(expected[:32], tag)
	for i := 32; i < len(expected); i++ {
		expected[i] = '0'
	}
	defer clear(actual[:])
	last := int64(-payloadSlotSize)
	for i, text := range entry.Offsets {
		n, e := payloadDecimal(text, math.MaxInt64/2)
		if e != nil || n < last+payloadSlotSize || size < payloadSlotSize || n > size-payloadSlotSize {
			return payloadInvalid
		}
		read, e := target.ReadAt(actual[:], n)
		if read != len(actual) || (e != nil && e != io.EOF) || !bytes.Equal(actual[:], expected[:]) {
			return payloadInvalid
		}
		positions[i], last = n, n
	}
	var encoded [64]byte
	hex.Encode(encoded[:], wm)
	defer clear(encoded[:])
	for _, n := range positions {
		wrote, e := target.WriteAt(encoded[:], n+32)
		if e != nil {
			return e
		}
		if wrote != len(encoded) {
			return io.ErrShortWrite
		}
	}
	return nil
}
