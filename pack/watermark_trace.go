package pack

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"syscall"
)

const traceMaxExpanded int64 = 512 << 20
const traceMaxEntry int64 = 128 << 20
const traceMaxDepth = 4
const traceMaxEntries = 4096
const traceMaxCandidates = 4096

var traceTagPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type TraceCandidate struct {
	Watermark string `json:"watermark"`
	Count     int64  `json:"count"`
}
type TraceResult struct {
	Status     string           `json:"status"`
	Watermark  string           `json:"watermark,omitempty"`
	Count      int64            `json:"count"`
	Slots      int64            `json:"slots"`
	Zeros      int64            `json:"zeros"`
	Complete   bool             `json:"complete"`
	Candidates []TraceCandidate `json:"candidates"`
	Warnings   []string         `json:"warnings"`
}
type traceState struct {
	ctx            context.Context
	tags           map[string]bool
	values         map[string]int64
	result         TraceResult
	expanded       int64
	entries, chunk int
}

func (s *traceState) incomplete(message string) {
	s.result.Complete = false
	for _, v := range s.result.Warnings {
		if v == message {
			return
		}
	}
	s.result.Warnings = append(s.result.Warnings, message)
}
func (s *traceState) active() bool {
	if s.ctx.Err() != nil {
		s.result.Status = "cancelled"
		s.incomplete("cancelled")
		return false
	}
	return true
}
func (s *traceState) raw(reader io.Reader) error {
	carry := []byte{}
	buffer := make([]byte, s.chunk)
	var processed, next int64
	for s.active() {
		n, err := reader.Read(buffer)
		if n > 0 {
			data := append(carry, buffer[:n]...)
			base := processed - int64(len(carry))
			for i := 0; i+96 <= len(data); i++ {
				if i&4095 == 0 && !s.active() {
					return s.ctx.Err()
				}
				if base+int64(i) < next || !s.tags[string(data[i:i+32])] {
					continue
				}
				value := data[i+32 : i+96]
				valid := true
				for _, b := range value {
					if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
						valid = false
						break
					}
				}
				if !valid {
					continue
				}
				text := string(value)
				if text != "0000000000000000000000000000000000000000000000000000000000000000" {
					if _, ok := s.values[text]; !ok && len(s.values) >= traceMaxCandidates {
						return errors.New("too many distinct watermark values")
					}
					s.values[text]++
				} else {
					s.result.Zeros++
				}
				s.result.Slots++
			}
			processed += int64(n)
			if processed >= 95 {
				next = processed - 95
			}
			start := len(data) - 95
			if start < 0 {
				start = 0
			}
			carry = append([]byte(nil), data[start:]...)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return s.ctx.Err()
}
func traceZIP(prefix []byte) bool {
	return len(prefix) >= 4 && prefix[0] == 'P' && prefix[1] == 'K' && (prefix[2] == 3 && prefix[3] == 4 || prefix[2] == 5 && prefix[3] == 6 || prefix[2] == 7 && prefix[3] == 8 || prefix[2] == 6 && prefix[3] == 6)
}
func traceRead(input io.ReaderAt, size, offset, length int64) ([]byte, error) {
	if offset < 0 || length < 0 || offset > size || length > size-offset || length > 65557 {
		return nil, errors.New("ZIP metadata bounds")
	}
	result := make([]byte, int(length))
	if _, err := input.ReadAt(result, offset); err != nil {
		return nil, errors.New("ZIP metadata truncated")
	}
	return result, nil
}
func traceU16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o : o+2]) }
func traceU32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o : o+4]) }
func traceExtra(extra []byte) error {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return errors.New("invalid ZIP extra")
		}
		id, n := traceU16(extra, 0), int(traceU16(extra, 2))
		extra = extra[4:]
		if n > len(extra) {
			return errors.New("invalid ZIP extra")
		}
		if id == 1 {
			return errors.New("ZIP64 unsupported")
		}
		extra = extra[n:]
	}
	return nil
}

type traceBudgetReader struct {
	s *traceState
	r io.Reader
	n int64
}

func (r *traceBudgetReader) Read(p []byte) (int, error) {
	if !r.s.active() {
		return 0, r.s.ctx.Err()
	}
	n, e := r.r.Read(p)
	r.n += int64(n)
	r.s.expanded += int64(n)
	if r.n > traceMaxEntry || r.s.expanded > traceMaxExpanded {
		return 0, errors.New("archive expansion limit")
	}
	return n, e
}
func (s *traceState) walk(input io.ReaderAt, size int64, depth int) error {
	if !s.active() {
		return s.ctx.Err()
	}
	var prefix [4]byte
	_, _ = input.ReadAt(prefix[:], 0)
	if !traceZIP(prefix[:]) {
		return s.raw(io.NewSectionReader(input, 0, size))
	}
	if depth > traceMaxDepth {
		return errors.New("nested archive depth limit")
	}
	tailSize := size
	if tailSize > 65557 {
		tailSize = 65557
	}
	tail, err := traceRead(input, size, size-tailSize, tailSize)
	if err != nil {
		return err
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if traceU32(tail, i) == 0x06054b50 && i+22+int(traceU16(tail, i+20)) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return errors.New("invalid or truncated ZIP")
	}
	count := int(traceU16(tail, end+10))
	centralSize, centralStart := int64(traceU32(tail, end+12)), int64(traceU32(tail, end+16))
	eocd := size - tailSize + int64(end)
	if count == 65535 || centralSize == 0xffffffff || centralStart == 0xffffffff {
		return errors.New("ZIP64 unsupported")
	}
	if eocd >= 20 {
		locator, e := traceRead(input, size, eocd-20, 4)
		if e != nil {
			return e
		}
		if traceU32(locator, 0) == 0x07064b50 {
			return errors.New("ZIP64 unsupported")
		}
	}
	if traceU16(tail, end+4) != 0 || traceU16(tail, end+6) != 0 || int(traceU16(tail, end+8)) != count {
		return errors.New("multidisk ZIP unsupported")
	}
	centralEnd := centralStart + centralSize
	if centralEnd != eocd || centralStart > size {
		return errors.New("ZIP directory bounds")
	}
	cursor := centralStart
	ranges := [][2]int64{}
	for i := 0; i < count; i++ {
		if !s.active() {
			return s.ctx.Err()
		}
		s.entries++
		if s.entries > traceMaxEntries {
			return errors.New("archive entry limit")
		}
		if cursor+46 > centralEnd {
			return errors.New("truncated ZIP directory")
		}
		header, e := traceRead(input, size, cursor, 46)
		if e != nil {
			return e
		}
		if traceU32(header, 0) != 0x02014b50 {
			return errors.New("invalid ZIP directory")
		}
		flags, method := traceU16(header, 8), traceU16(header, 10)
		checksum := traceU32(header, 16)
		compressed, length, local := int64(traceU32(header, 20)), int64(traceU32(header, 24)), int64(traceU32(header, 42))
		nameLength, extraLength, commentLength := int64(traceU16(header, 28)), int64(traceU16(header, 30)), int64(traceU16(header, 32))
		next := cursor + 46 + nameLength + extraLength + commentLength
		if next > centralEnd {
			return errors.New("ZIP directory overflow")
		}
		extra, e := traceRead(input, size, cursor+46+nameLength, extraLength)
		if e != nil {
			return e
		}
		cursor = next
		if compressed == 0xffffffff || length == 0xffffffff || local == 0xffffffff || traceU16(header, 6) >= 45 || traceU16(header, 34) != 0 {
			return errors.New("ZIP64 or advanced ZIP unsupported")
		}
		if e = traceExtra(extra); e != nil {
			return e
		}
		if flags & ^uint16(2|4|8|2048) != 0 || method != 0 && method != 8 {
			return errors.New("encrypted or unsupported ZIP entry")
		}
		if length > traceMaxEntry || length > traceMaxExpanded-s.expanded {
			return errors.New("archive expansion limit")
		}
		if local+30 > centralStart {
			return errors.New("local ZIP header bounds")
		}
		lh, e := traceRead(input, size, local, 30)
		if e != nil {
			return e
		}
		if traceU32(lh, 0) != 0x04034b50 || traceU16(lh, 6) != flags || traceU16(lh, 8) != method {
			return errors.New("local ZIP header mismatch")
		}
		localExtraStart := local + 30 + int64(traceU16(lh, 26))
		localExtra, e := traceRead(input, size, localExtraStart, int64(traceU16(lh, 28)))
		if e != nil {
			return e
		}
		if traceU16(lh, 4) >= 45 || traceU32(lh, 18) == 0xffffffff || traceU32(lh, 22) == 0xffffffff {
			return errors.New("local ZIP64 unsupported")
		}
		if e = traceExtra(localExtra); e != nil {
			return e
		}
		if flags&8 == 0 && (traceU32(lh, 14) != checksum || int64(traceU32(lh, 18)) != compressed || int64(traceU32(lh, 22)) != length) {
			return errors.New("local ZIP size or CRC mismatch")
		}
		dataStart := localExtraStart + int64(len(localExtra))
		dataEnd := dataStart + compressed
		if dataStart > centralStart || dataEnd > centralStart {
			return errors.New("ZIP entry bounds")
		}
		for _, r := range ranges {
			if local < r[1] && dataEnd > r[0] {
				return errors.New("overlapping ZIP entries")
			}
		}
		ranges = append(ranges, [2]int64{local, dataEnd})
		var stream io.Reader = io.NewSectionReader(input, dataStart, compressed)
		var closer io.Closer
		if method == 8 {
			decoder := flate.NewReader(stream)
			stream = decoder
			closer = decoder
		}
		content, e := io.ReadAll(&traceBudgetReader{s: s, r: stream})
		if closer != nil {
			closeError := closer.Close()
			if e == nil {
				e = closeError
			}
		}
		if e != nil || int64(len(content)) != length || crc32.ChecksumIEEE(content) != checksum {
			return errors.New("ZIP entry integrity or expansion failure")
		}
		if e = s.walk(bytes.NewReader(content), int64(len(content)), depth+1); e != nil {
			return e
		}
	}
	if cursor != centralEnd {
		return errors.New("unrecognized ZIP directory data")
	}
	return nil
}
func (s *traceState) finish() TraceResult {
	for value, count := range s.values {
		s.result.Candidates = append(s.result.Candidates, TraceCandidate{value, count})
	}
	sort.Slice(s.result.Candidates, func(i, j int) bool {
		a, b := s.result.Candidates[i], s.result.Candidates[j]
		if a.Count == b.Count {
			return a.Watermark < b.Watermark
		}
		return a.Count > b.Count
	})
	if len(s.result.Candidates) > 0 {
		s.result.Count = s.result.Candidates[0].Count
	}
	if s.result.Status == "cancelled" {
		return s.result
	}
	if !s.result.Complete {
		s.result.Status = "partial"
		return s.result
	}
	switch {
	case len(s.result.Candidates) == 0 && s.result.Zeros > 0:
		s.result.Status = "zero"
	case len(s.result.Candidates) == 0:
		s.result.Status = "none"
	case len(s.result.Candidates) > 1 && s.result.Candidates[0].Count == s.result.Candidates[1].Count:
		s.result.Status = "ambiguous"
	default:
		s.result.Status = "found"
		s.result.Watermark = s.result.Candidates[0].Watermark
	}
	return s.result
}
func scanWatermark(ctx context.Context, input io.ReaderAt, size int64, tags []string, chunk int) (TraceResult, error) {
	if size < 0 || len(tags) == 0 || len(tags) > 65535 || chunk < 1 || chunk > 1<<20 {
		return TraceResult{}, errors.New("invalid trace parameters")
	}
	s := traceState{ctx: ctx, tags: map[string]bool{}, values: map[string]int64{}, chunk: chunk, result: TraceResult{Complete: true, Candidates: []TraceCandidate{}, Warnings: []string{}}}
	for _, tag := range tags {
		if !traceTagPattern.MatchString(tag) {
			return TraceResult{}, errors.New("invalid software tag")
		}
		s.tags[tag] = true
	}
	var prefix [4]byte
	_, _ = input.ReadAt(prefix[:], 0)
	if !traceZIP(prefix[:]) {
		s.result.Warnings = append(s.result.Warnings, "raw byte scan; non-ZIP compression is not unpacked")
	}
	if err := s.walk(input, size, 0); err != nil {
		s.incomplete(err.Error())
	}
	return s.finish(), nil
}

// ScanWatermark scans a raw file incrementally or bounded ZIP/JAR entries. Tags
// identify software only, never an authorization. Incomplete/ambiguous output
// must not be treated as an automatically identified license.
func ScanWatermark(ctx context.Context, input io.ReaderAt, size int64, tags []string) (TraceResult, error) {
	return scanWatermark(ctx, input, size, tags, 65536)
}

type traceTags []string

func (t *traceTags) String() string { return "" }
func (t *traceTags) Set(v string) error {
	if !traceTagPattern.MatchString(v) {
		return errors.New("invalid tag")
	}
	*t = append(*t, v)
	return nil
}
func runTrace(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("trace", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var tags traceTags
	flags.Var(&tags, "tag", "")
	if flags.Parse(args) != nil || flags.NArg() != 1 || len(tags) == 0 {
		fmt.Fprintln(stderr, "usage: authgo-pack trace --tag <32 lowercase hex> [--tag <tag>] <file>")
		return 1
	}
	file, err := openSafe(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "trace input unavailable")
		return 1
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		fmt.Fprintln(stderr, "trace requires a regular file")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := ScanWatermark(ctx, file, stat.Size(), tags)
	if err != nil {
		fmt.Fprintln(stderr, "trace parameters invalid")
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 1
	}
	if !result.Complete {
		return 2
	}
	return 0
}
