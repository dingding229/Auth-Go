package pack

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

type phpToken struct {
	text       string
	start, end int64
}
type phpWatermarkLex struct {
	window watermarkWindow
	pos    int64
	php    bool
}

func phpIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 128
}
func phpIdentPart(c byte) bool { return phpIdent(c) || c >= '0' && c <= '9' }
func (l *phpWatermarkLex) quote(at int64, quote byte) (int64, error) {
	at++
	for at < l.window.size {
		c, _ := l.window.get(at)
		if c == '\\' {
			at += 2
			continue
		}
		if c == quote {
			return at + 1, nil
		}
		next, _ := l.window.get(at + 1)
		if quote != '\'' && (c == '{' && next == '$' || c == '$' && next == '{') {
			at += 2
			depth := 1
			for at < l.window.size && depth > 0 {
				c, _ = l.window.get(at)
				if c == '\'' || c == '"' || c == '`' {
					var e error
					at, e = l.quote(at, c)
					if e != nil {
						return 0, e
					}
					continue
				}
				if c == '{' {
					depth++
				}
				if c == '}' {
					depth--
				}
				at++
			}
			if depth != 0 {
				return 0, errors.New("unterminated PHP interpolation")
			}
			continue
		}
		at++
	}
	return 0, errors.New("unterminated PHP string")
}
func (l *phpWatermarkLex) heredoc(at int64) (int64, error) {
	at += 3
	for {
		c, e := l.window.get(at)
		if e != nil {
			return 0, errors.New("invalid PHP heredoc")
		}
		if c != ' ' && c != '\t' {
			break
		}
		at++
	}
	quote := byte(0)
	if c, _ := l.window.get(at); c == '\'' || c == '"' {
		quote = c
		at++
	}
	label := []byte{}
	for {
		c, e := l.window.get(at)
		if e != nil || !phpIdentPart(c) {
			break
		}
		label = append(label, c)
		at++
		if len(label) > 65535 {
			return 0, errors.New("PHP heredoc label too long")
		}
	}
	if len(label) == 0 || !phpIdent(label[0]) {
		return 0, errors.New("invalid PHP heredoc label")
	}
	if quote != 0 {
		c, _ := l.window.get(at)
		if c != quote {
			return 0, errors.New("invalid PHP heredoc quote")
		}
		at++
	}
	for at < l.window.size {
		c, _ := l.window.get(at)
		at++
		if c == '\n' {
			break
		}
		if c != '\r' && c != ' ' && c != '\t' {
			return 0, errors.New("invalid PHP heredoc header")
		}
	}
	for at < l.window.size {
		start := at
		for {
			c, e := l.window.get(start)
			if e != nil {
				break
			}
			if c != ' ' && c != '\t' {
				break
			}
			start++
		}
		match := true
		for i, c := range label {
			x, e := l.window.get(start + int64(i))
			if e != nil || x != c {
				match = false
				break
			}
		}
		if match {
			after := start + int64(len(label))
			c, e := l.window.get(after)
			if e == io.EOF || !phpIdentPart(c) {
				return after, nil
			}
		}
		for at < l.window.size {
			c, _ := l.window.get(at)
			at++
			if c == '\n' {
				break
			}
		}
	}
	return 0, errors.New("unterminated PHP heredoc")
}
func (l *phpWatermarkLex) next() (phpToken, error) {
	for l.pos < l.window.size {
		start := l.pos
		c, _ := l.window.get(start)
		n, _ := l.window.get(start + 1)
		if !l.php {
			var open [5]byte
			for i := range open {
				open[i], _ = l.window.get(start + int64(i))
			}
			if strings.EqualFold(string(open[:]), "<?php") {
				after, e := l.window.get(start + 5)
				if e == io.EOF || after == ' ' || after == '\t' || after == '\r' || after == '\n' {
					l.php = true
					l.pos += 5
					return phpToken{"open", start, l.pos}, nil
				}
			}
			if c == '<' && n == '?' {
				third, _ := l.window.get(start + 2)
				if third == '=' {
					l.php = true
					l.pos += 3
					return phpToken{"echo-open", start, l.pos}, nil
				}
			}
			l.pos++
			continue
		}
		if c == '?' && n == '>' {
			l.php = false
			l.pos += 2
			return phpToken{"close", start, l.pos}, nil
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' {
			l.pos++
			continue
		}
		if c == '/' && n == '/' || c == '#' && n != '[' {
			for l.pos < l.window.size {
				c, _ = l.window.get(l.pos)
				n, _ = l.window.get(l.pos + 1)
				if c == '\n' || c == '\r' || c == '?' && n == '>' {
					break
				}
				l.pos++
			}
			continue
		}
		if c == '/' && n == '*' {
			l.pos += 2
			closed := false
			for l.pos < l.window.size {
				c, _ = l.window.get(l.pos)
				n, _ = l.window.get(l.pos + 1)
				if c == '*' && n == '/' {
					l.pos += 2
					closed = true
					break
				}
				l.pos++
			}
			if !closed {
				return phpToken{}, errors.New("unterminated PHP comment")
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			end, e := l.quote(start, c)
			if e != nil {
				return phpToken{}, e
			}
			l.pos = end
			return phpToken{"literal", start, end}, nil
		}
		if c == '<' && n == '<' {
			third, _ := l.window.get(start + 2)
			if third == '<' {
				end, e := l.heredoc(start)
				if e != nil {
					return phpToken{}, e
				}
				l.pos = end
				return phpToken{"literal", start, end}, nil
			}
		}
		// Variables and qualified names are single tokens, not keyword substrings.
		if c == '$' && phpIdent(n) {
			l.pos += 2
			for l.pos < l.window.size {
				x, _ := l.window.get(l.pos)
				if !phpIdentPart(x) {
					break
				}
				l.pos++
			}
			return phpToken{"variable", start, l.pos}, nil
		}
		if c == '-' && n == '>' || c == ':' && n == ':' {
			l.pos += 2
			return phpToken{string([]byte{c, n}), start, l.pos}, nil
		}
		if c == '?' && n == '-' {
			third, _ := l.window.get(start + 2)
			if third == '>' {
				l.pos += 3
				return phpToken{"?->", start, l.pos}, nil
			}
		}
		if c == '\\' {
			l.pos++
			for l.pos < l.window.size {
				x, _ := l.window.get(l.pos)
				if !phpIdentPart(x) && x != '\\' {
					break
				}
				l.pos++
			}
			return phpToken{"qualified-name", start, l.pos}, nil
		}
		if phpIdent(c) {
			word := []byte{}
			for l.pos < l.window.size {
				x, _ := l.window.get(l.pos)
				if !phpIdentPart(x) && x != '\\' {
					break
				}
				word = append(word, x)
				l.pos++
				if len(word) > 65535 {
					return phpToken{}, errors.New("PHP token too long")
				}
			}
			if strings.ContainsRune(string(word), '\\') {
				return phpToken{"qualified-name", start, l.pos}, nil
			}
			return phpToken{strings.ToLower(string(word)), start, l.pos}, nil
		}
		l.pos++
		return phpToken{string([]byte{c}), start, l.pos}, nil
	}
	return phpToken{}, io.EOF
}
func phpRootInsertion(file *os.File, size int64) (int64, error) {
	lex := phpWatermarkLex{window: watermarkWindow{file: file, size: size}}
	first, e := lex.next()
	if e != nil || first.text != "open" {
		return 0, errors.New("PHP watermark requires a long-tag core script")
	}
	at := first.end
	for {
		token, e := lex.next()
		if e == io.EOF {
			return at, nil
		}
		if e != nil {
			return 0, e
		}
		if token.text == "declare" {
			open, e := lex.next()
			if e != nil || open.text != "(" {
				return 0, errors.New("unsupported PHP declare")
			}
			depth := 1
			for depth > 0 {
				next, e := lex.next()
				if e != nil {
					return 0, e
				}
				if next.text == "(" {
					depth++
				}
				if next.text == ")" {
					depth--
				}
			}
			end, e := lex.next()
			if e != nil {
				return 0, e
			}
			if end.text == ";" {
				at = end.end
				continue
			}
			if end.text == "{" || end.text == ":" {
				return end.end, nil
			}
			return 0, errors.New("unsupported PHP declare body")
		}
		if token.text == "namespace" {
			for {
				next, e := lex.next()
				if e != nil {
					return 0, e
				}
				if next.text == ";" || next.text == "{" {
					return next.end, nil
				}
				if next.text == "(" || next.text == "close" {
					return 0, errors.New("unsupported PHP namespace prologue")
				}
			}
		}
		return at, nil
	}
}
func phpFunctionInsertions(file *os.File, size int64) ([]int64, error) {
	lex := phpWatermarkLex{window: watermarkWindow{file: file, size: size}}
	out := []int64{}
	previous := ""
	for {
		token, e := lex.next()
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		before := previous
		previous = token.text
		if token.text != "function" || before == "->" || before == "?->" || before == "::" || before == "namespace" || before == "function" {
			continue
		}
		look := lex
		// A declaration has [ & ] [ name ] '(' immediately after function.
		// Never scan arbitrary calls/assignments ahead looking for a later '{'.
		next, e := look.next()
		if e != nil {
			if e == io.EOF {
				continue
			}
			return nil, e
		}
		if next.text == "&" {
			next, e = look.next()
			if e != nil {
				if e == io.EOF {
					continue
				}
				return nil, e
			}
		}
		if next.text != "(" {
			if next.text == "variable" || next.text == "qualified-name" || next.text == "" || !phpIdent(next.text[0]) {
				continue
			}
			next, e = look.next()
			if e != nil {
				if e == io.EOF {
					continue
				}
				return nil, e
			}
		}
		if next.text != "(" {
			continue
		}
		depth := 1
		parameters := true
		for {
			next, e := look.next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, e
			}
			if next.text == "close" || next.text == ";" {
				break
			}
			if next.text == "(" {
				depth++
				parameters = true
			}
			if next.text == ")" {
				depth--
				if depth < 0 {
					break
				}
			}
			if next.text == "{" && depth == 0 {
				if parameters {
					out = append(out, next.end)
				}
				break
			}
		}
	}
}
func phpSlotBlock(tag string, static bool) ([]byte, []int64, error) {
	var random [32]byte
	if _, e := io.ReadFull(rand.Reader, random[:]); e != nil {
		return nil, nil, errors.New("watermark randomness failed")
	}
	defer clear(random[:])
	var prefix string
	if static {
		prefix = " (static function() { static $__authgo_watermark_" + hex.EncodeToString(random[:16]) + " = ["
	} else {
		prefix = " (static function(array $values): void { $name = '__authgo_watermark_" + hex.EncodeToString(random[:16]) + "_' . \\hash('sha256', $values[0]); if (!\\defined($name)) { \\define($name, $values); } })(["
	}
	data := []byte(prefix)
	offsets := []int64{}
	for i := 0; i < 8; i++ {
		if i > 0 {
			data = append(data, ',')
		}
		label := watermarkSlotLabel(random[:], i)
		offsets = append(offsets, int64(len(data)+1+len(label)))
		data = append(data, '\'')
		data = append(data, label...)
		data = append(data, tag...)
		data = append(data, strings.Repeat("0", 64)...)
		data = append(data, '\'')
	}
	data = append(data, ']')
	if !static {
		data = append(data, ')', ';')
	} else {
		data = append(data, []byte("; return $__authgo_watermark_"+hex.EncodeToString(random[:16])+"; })();")...)
	}
	return data, offsets, nil
}
func preparePHPWatermark(input source, tag string) (source, []watermarkIndexEntry, error) {
	if input.file.Kind != "php" || input.file.Encoding != "tar" {
		return source{}, nil, invalid
	}
	input.entryEdits = map[string][]watermarkEdit{}
	input.entrySizes = map[string]int64{}
	descriptors := []watermarkIndexEntry{}
	total := 0
	for _, entry := range input.entries {
		file, e := openSafe(entry.path)
		if e != nil {
			return source{}, nil, e
		}
		stat, e := file.Stat()
		if e != nil || !os.SameFile(entry.info, stat) || stat.Size() != entry.info.Size() || !stat.ModTime().Equal(entry.info.ModTime()) {
			file.Close()
			return source{}, nil, errors.New("input changed")
		}
		root, e := phpRootInsertion(file, stat.Size())
		if e != nil {
			file.Close()
			return source{}, nil, e
		}
		functions, e := phpFunctionInsertions(file, stat.Size())
		file.Close()
		if e != nil {
			return source{}, nil, e
		}
		positions := append([]int64{root}, functions...)
		sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
		edits := []watermarkEdit{}
		offsets := []string{}
		var delta int64
		for _, at := range positions {
			block, inside, e := phpSlotBlock(tag, at != root)
			if e != nil {
				return source{}, nil, e
			}
			for _, offset := range inside {
				offsets = append(offsets, strconv.FormatInt(at+delta+offset, 10))
			}
			edits = append(edits, watermarkEdit{at: at, insert: block})
			delta += int64(len(block))
		}
		total += len(offsets)
		if total > 65535 {
			return source{}, nil, errors.New("too many PHP watermark slots")
		}
		input.entryEdits[entry.name] = edits
		input.entrySizes[entry.name] = stat.Size() + delta
		descriptors = append(descriptors, watermarkIndexEntry{Path: []string{entry.name}, Offsets: offsets})
	}
	var count counter
	if e := input.writeArchive(&count); e != nil {
		return source{}, nil, e
	}
	input.file.Size = int64(count)
	return input, descriptors, nil
}
func CreateWatermarkedPHP(input, destination string, p Payload, public []byte) error {
	original, e := inspect("php", "core", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := preparePHPWatermark(original, tag)
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
