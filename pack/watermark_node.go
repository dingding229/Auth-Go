package pack

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"unicode"
	"unicode/utf8"
)

type watermarkReadCloser struct {
	io.Reader
	io.Closer
}
type watermarkWindow struct {
	file        *os.File
	size, start int64
	data        []byte
}

func (w *watermarkWindow) get(at int64) (byte, error) {
	if at < 0 || at >= w.size {
		return 0, io.EOF
	}
	if w.data == nil || at < w.start || at >= w.start+int64(len(w.data)) {
		w.start = at / 65536 * 65536
		n := int64(65536)
		if w.size-w.start < n {
			n = w.size - w.start
		}
		w.data = make([]byte, int(n))
		if _, e := w.file.ReadAt(w.data, w.start); e != nil {
			return 0, e
		}
	}
	return w.data[at-w.start], nil
}
func (w *watermarkWindow) rune(at int64) (rune, int, error) {
	var raw [4]byte
	n := 0
	for n < 4 && at+int64(n) < w.size {
		b, e := w.get(at + int64(n))
		if e != nil {
			return 0, 0, e
		}
		raw[n] = b
		n++
		if utf8.FullRune(raw[:n]) {
			break
		}
	}
	if n == 0 {
		return 0, 0, io.EOF
	}
	r, size := utf8.DecodeRune(raw[:n])
	if r == utf8.RuneError && size == 1 {
		return 0, 0, errors.New("invalid UTF-8 directive prologue")
	}
	return r, size, nil
}
func jsWhite(r rune) bool {
	return r == '\t' || r == '\v' || r == '\f' || r == '\r' || r == '\n' || r == 0xfeff || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Zs, r)
}
func jsLine(r rune) bool { return r == '\r' || r == '\n' || r == 0x2028 || r == 0x2029 }
func (w *watermarkWindow) trivia(at int64) (int64, bool, error) {
	line := false
	for at < w.size {
		r, n, e := w.rune(at)
		if e != nil {
			return 0, false, e
		}
		if jsWhite(r) {
			line = line || jsLine(r)
			at += int64(n)
			continue
		}
		b, _ := w.get(at)
		next, _ := w.get(at + 1)
		if b == '/' && next == '/' {
			at += 2
			for at < w.size {
				r, n, e = w.rune(at)
				if e != nil {
					return 0, false, e
				}
				if jsLine(r) {
					break
				}
				at += int64(n)
			}
			continue
		}
		if b == '/' && next == '*' {
			at += 2
			closed := false
			for at < w.size {
				b, _ = w.get(at)
				next, _ = w.get(at + 1)
				if b == '*' && next == '/' {
					at += 2
					closed = true
					break
				}
				r, n, e = w.rune(at)
				if e != nil {
					return 0, false, e
				}
				line = line || jsLine(r)
				at += int64(n)
			}
			if !closed {
				return 0, false, errors.New("unterminated CommonJS comment")
			}
			continue
		}
		break
	}
	return at, line, nil
}
func (w *watermarkWindow) literal(at int64) (int64, error) {
	quote, e := w.get(at)
	if e != nil {
		return 0, e
	}
	at++
	for at < w.size {
		b, _ := w.get(at)
		if b == quote {
			return at + 1, nil
		}
		if b == '\n' || b == '\r' {
			return 0, errors.New("unterminated CommonJS directive")
		}
		if b == '\\' {
			at++
			if at >= w.size {
				return 0, errors.New("unterminated CommonJS escape")
			}
			b, _ = w.get(at)
			if b == '\r' {
				next, _ := w.get(at + 1)
				at++
				if next == '\n' {
					at++
				}
			} else {
				_, n, e := w.rune(at)
				if e != nil {
					return 0, e
				}
				at += int64(n)
			}
			continue
		}
		_, n, e := w.rune(at)
		if e != nil {
			return 0, e
		}
		at += int64(n)
	}
	return 0, errors.New("unterminated CommonJS directive")
}
func (w *watermarkWindow) continues(at int64, line bool) bool {
	b, e := w.get(at)
	if e != nil {
		return false
	}
	next, _ := w.get(at + 1)
	if (b == '+' && next == '+' || b == '-' && next == '-') && line {
		return false
	}
	if bytes.IndexByte([]byte(".([`+-*/%?:<>=&|^,"), b) >= 0 {
		return true
	}
	if b == '!' && next == '=' {
		return true
	}
	for _, word := range []string{"in", "instanceof"} {
		match := true
		for i := range word {
			x, e := w.get(at + int64(i))
			if e != nil || x != word[i] {
				match = false
				break
			}
		}
		if match {
			x, e := w.get(at + int64(len(word)))
			if e == io.EOF || !(x >= 'a' && x <= 'z' || x >= 'A' && x <= 'Z' || x >= '0' && x <= '9' || x == '_' || x == '$' || x >= 128) {
				return true
			}
		}
	}
	return false
}

// Preserve the Directive Prologue, including ASI and escaped string literals.
// The injected statement has no line breaks, so original source line numbers
// remain stable (columns/introspective metadata are necessarily different).
func nodeWatermarkInsertion(file *os.File, size int64) (int64, error) {
	w := watermarkWindow{file: file, size: size}
	base := int64(0)
	if a, _ := w.get(0); a == 0xef {
		b, _ := w.get(1)
		c, _ := w.get(2)
		if b == 0xbb && c == 0xbf {
			base = 3
		}
	}
	if a, _ := w.get(base); a == '#' {
		b, _ := w.get(base + 1)
		if b == '!' {
			for base < size {
				r, n, e := w.rune(base)
				if e != nil {
					return 0, e
				}
				base += int64(n)
				if jsLine(r) {
					break
				}
			}
			if base == size {
				last, _ := w.get(size - 1)
				if last != '\n' && last != '\r' {
					return base, nil
				}
			}
		}
	}
	result, cursor := base, base
	for {
		start, _, e := w.trivia(cursor)
		if e != nil {
			return 0, e
		}
		if start == size {
			return result, nil
		}
		quote, _ := w.get(start)
		if quote != '\'' && quote != '"' {
			return result, nil
		}
		end, e := w.literal(start)
		if e != nil {
			return 0, e
		}
		next, line, e := w.trivia(end)
		if e != nil {
			return 0, e
		}
		token, e := w.get(next)
		if e == io.EOF {
			return end, nil
		}
		if token == ';' {
			result = next + 1
			cursor = next + 1
			continue
		}
		if !line || w.continues(next, line) {
			return result, nil
		}
		result = end
		cursor = next
	}
}
func prepareNodeWatermark(input source, tag string) (source, []watermarkIndexEntry, error) {
	if input.file.Kind != "node" || input.file.Encoding != "raw" || len(tag) != 32 {
		return source{}, nil, invalid
	}
	file, e := openSafe(input.path)
	if e != nil {
		return source{}, nil, e
	}
	defer file.Close()
	stat, e := file.Stat()
	if e != nil || !os.SameFile(input.info, stat) || stat.Size() != input.info.Size() || !stat.ModTime().Equal(input.info.ModTime()) {
		return source{}, nil, errors.New("input changed")
	}
	at, e := nodeWatermarkInsertion(file, stat.Size())
	if e != nil {
		return source{}, nil, e
	}
	random := make([]byte, 32)
	if _, e = io.ReadFull(rand.Reader, random); e != nil {
		return source{}, nil, errors.New("watermark randomness failed")
	}
	defer clear(random)
	// A pure expression has no identifier lookup, property access or mutation.
	// In particular CommonJS top-level this is public exports, not private storage.
	// The loader privately retains the exact successfully executed source instead.
	prefix := ";void ["
	// A shebang at EOF needs a terminator before the metadata statement.
	if at == stat.Size() && at > 0 {
		var last [1]byte
		_, _ = file.ReadAt(last[:], at-1)
		var head [5]byte
		_, _ = file.ReadAt(head[:], 0)
		shebang := string(head[:2]) == "#!" || bytes.Equal(head[:3], []byte{0xef, 0xbb, 0xbf}) && string(head[3:]) == "#!"
		if shebang && last[0] != '\n' && last[0] != '\r' {
			prefix = "\n" + prefix
		}
	}
	block := []byte(prefix)
	offsets := []string{}
	for i := 0; i < 8; i++ {
		if i > 0 {
			block = append(block, ',')
		}
		label := watermarkSlotLabel(random[:], i)
		value := label + tag + "0000000000000000000000000000000000000000000000000000000000000000"
		literal, e := json.Marshal(value)
		if e != nil {
			return source{}, nil, e
		}
		offsets = append(offsets, strconv.FormatInt(at+int64(len(block)+1+len(label)), 10))
		block = append(block, literal...)
	}
	block = append(block, []byte("];")...)
	if input.file.Size > math.MaxInt64/2-int64(len(block)) {
		return source{}, nil, errors.New("watermarked source too large")
	}
	input.insertAt = at
	input.inserted = block
	input.file.Size += int64(len(block))
	return input, []watermarkIndexEntry{{Path: []string{}, Offsets: offsets}}, nil
}

// CreateWatermarkedNode is the single-core v2 build entry point. The normal CLI uses the same v2 emission rules.
func CreateWatermarkedNode(input, destination string, p Payload, public []byte) error {
	original, e := inspect("node", "core", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := prepareNodeWatermark(original, tag)
	if e != nil {
		return e
	}
	code.file.Path = cipherName(0)
	private, e := json.Marshal(watermarkIndex{V: "1", Tag: tag, Files: []watermarkIndexFile{{Index: "0", Entries: entries}}})
	if e != nil || len(private) > watermarkIndexMax {
		return invalid
	}
	meta := source{file: File{Name: watermarkIndexName, Kind: "watermark", Path: cipherName(1), Size: int64(len(private)), Encoding: "raw", ChunkSize: ChunkSize}, generated: private}
	p.V = 2
	p, key, e := NewPayload(p, Manifest{Files: []File{code.file, meta.file}}, public)
	if e != nil {
		return e
	}
	defer clear(key)
	return publish(destination, []source{code, meta}, p, key)
}
