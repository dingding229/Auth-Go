package pack

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
)

type watermarkEdit struct {
	at, remove       int64
	insert, expected []byte
	// pieces streams a graph rewrite without buffering bytecode/string bodies.
	pieces []watermarkMarshalPiece
}

func watermarkEditedReader(file *os.File, size int64, edits []watermarkEdit) (io.Reader, error) {
	readers := []io.Reader{}
	var cursor int64
	for _, edit := range edits {
		if edit.at < cursor || edit.remove < 0 || edit.at > size || edit.remove > size-edit.at {
			return nil, errors.New("invalid watermark edit bounds")
		}
		if len(edit.expected) > 0 {
			actual := make([]byte, len(edit.expected))
			if _, e := file.ReadAt(actual, edit.at); e != nil || string(actual) != string(edit.expected) {
				return nil, errors.New("watermark input changed")
			}
		}
		readers = append(readers, io.NewSectionReader(file, cursor, edit.at-cursor), &watermarkSliceReader{data: edit.insert})
		for _, piece := range edit.pieces {
			if piece.data != nil {
				readers = append(readers, &watermarkSliceReader{data: piece.data})
			} else {
				if piece.at < 0 || piece.size < 0 || piece.at > size || piece.size > size-piece.at {
					return nil, errors.New("invalid Python marshal piece bounds")
				}
				readers = append(readers, io.NewSectionReader(file, piece.at, piece.size))
			}
		}
		cursor = edit.at + edit.remove
	}
	readers = append(readers, io.NewSectionReader(file, cursor, size-cursor))
	return io.MultiReader(readers...), nil
}

type watermarkSliceReader struct {
	data []byte
	at   int
}

func (r *watermarkSliceReader) Read(b []byte) (int, error) {
	if r.at == len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.at:])
	r.at += n
	return n, nil
}

// A reference edge has its own wire span; the target retains its definition
// span. In particular a co_consts field may itself be TYPE_REF, and many fields
// may alias a single (even empty) tuple.
type watermarkMarshalEdge struct {
	start, end int64
	value      *watermarkMarshalValue
	constants  bool
}

type watermarkMarshalValue struct {
	kind             byte
	raw              byte
	start, head, end int64
	n                int64
	available        bool
	children         []watermarkMarshalEdge
}

type watermarkMarshal struct {
	window                  watermarkWindow
	pos                     int64
	version, depth, objects int
	refs                    []*watermarkMarshalValue
	codes                   int
}

func (r *watermarkMarshal) take(n int64) int64 {
	if n < 0 || n > r.window.size-r.pos {
		panic("truncated Python marshal")
	}
	at := r.pos
	r.pos += n
	return at
}
func (r *watermarkMarshal) byte() byte {
	at := r.take(1)
	v, e := r.window.get(at)
	if e != nil {
		panic("Python marshal unreadable")
	}
	return v
}
func (r *watermarkMarshal) i32() int64 {
	at := r.take(4)
	var b [4]byte
	for i := range b {
		v, e := r.window.get(at + int64(i))
		if e != nil {
			panic("Python marshal unreadable")
		}
		b[i] = v
	}
	return int64(int32(binary.LittleEndian.Uint32(b[:])))
}
func (r *watermarkMarshal) object(nullable bool) (edge watermarkMarshalEdge) {
	r.depth++
	r.objects++
	defer func() { r.depth-- }()
	if r.depth > 128 || r.objects > 1<<20 {
		panic("Python marshal resource limit")
	}
	edge.start = r.pos
	tag := r.byte()
	kind := tag & 127
	if kind == 'r' {
		if tag&128 != 0 {
			panic("invalid Python marshal reference flag")
		}
		id := r.i32()
		if id < 0 || id >= int64(len(r.refs)) || !r.refs[id].available {
			panic("invalid or unfinished Python marshal reference")
		}
		edge.value, edge.end = r.refs[id], r.pos
		return edge
	}
	value := &watermarkMarshalValue{kind: kind, raw: kind, start: edge.start, available: kind != 'c' && kind != '>' && kind != ':'}
	edge.value = value
	if tag&128 != 0 {
		switch kind {
		case '0', 'N', 'F', 'T', 'S', '.':
			panic("unsupported Python marshal singleton reference flag")
		}
		if len(r.refs) >= 1<<20 {
			panic("Python marshal reference limit")
		}
		r.refs = append(r.refs, value)
	}
	child := func(nullable bool) watermarkMarshalEdge {
		v := r.object(nullable)
		value.children = append(value.children, v)
		return v
	}
	need := func(kind byte) {
		v := child(false)
		if v.value.kind != kind {
			panic("invalid Python code field type")
		}
	}
	text := func() {
		v := child(false)
		switch v.value.kind {
		case 'u', 't', 'a', 'A', 'z', 'Z':
		default:
			panic("invalid Python code text")
		}
	}
	switch kind {
	case '0':
		if !nullable {
			panic("unexpected Python marshal null")
		}
	case 'N', 'F', 'T', 'S', '.':
	case 'i':
		r.take(4)
	case 'I', 'g':
		r.take(8)
	case 'y':
		r.take(16)
	case 'l':
		n := r.i32()
		if n < 0 {
			n = -n
		}
		if n > r.window.size/2 {
			panic("Python long overflow")
		}
		r.take(n * 2)
	case 'f':
		r.take(int64(r.byte()))
	case 'x':
		r.take(int64(r.byte()))
		r.take(int64(r.byte()))
	case 's', 't', 'u', 'a', 'A':
		r.take(r.i32())
	case 'z', 'Z':
		r.take(int64(r.byte()))
	case '(', ')', '[', '<', '>':
		if kind == ')' {
			value.kind = '('
			value.n = int64(r.byte())
		} else {
			value.n = r.i32()
		}
		value.head = r.pos
		if value.n < 0 || value.n > r.window.size {
			panic("Python sequence limit")
		}
		for i := int64(0); i < value.n; i++ {
			child(false)
		}
	case '{':
		for {
			key := child(true)
			if key.value.kind == '0' {
				break
			}
			child(false)
		}
	case ':':
		if r.version < 314 {
			panic("unsupported Python slice before 3.14")
		}
		child(false)
		child(false)
		child(false)
	case 'c':
		r.codes++
		fields := 6
		if r.version >= 311 {
			fields = 5
		}
		for i := 0; i < fields; i++ {
			if r.i32() < 0 {
				panic("negative Python code field")
			}
		}
		need('s')
		need('(')
		value.children[len(value.children)-1].constants = true
		need('(')
		if r.version < 311 {
			need('(')
			need('(')
			need('(')
		} else {
			need('(')
			need('s')
		}
		text()
		text()
		if r.version >= 311 {
			text()
		}
		if r.i32() < 0 {
			panic("invalid Python line number")
		}
		need('s')
		if r.version >= 311 {
			need('s')
		}
	default:
		panic(fmt.Sprintf("unsupported Python marshal type 0x%02x at %d", kind, value.start))
	}
	value.available = true
	value.end, edge.end = r.pos, r.pos
	return edge
}

// References are GLOBAL to a marshal stream, not scoped to a code object.
// Re-emitting the graph (rather than copying TYPE_REF's old integer) also lets
// us split a constants tuple from its names/varnames/freevars aliases. The old
// tuple remains shared by ordinary edges; code constant edges share a separate
// appended tuple. Code objects themselves are never cloned.
type watermarkMarshalIdentity struct {
	value     *watermarkMarshalValue
	constants bool
}

type watermarkMarshalPiece struct {
	at, size int64
	data     []byte
}

type watermarkMarshalWriter struct {
	pieces  []watermarkMarshalPiece
	size    int64
	refs    map[watermarkMarshalIdentity]uint32
	active  map[watermarkMarshalIdentity]bool
	offsets []string
	random  [32]byte
	tag     string
	depth   int
}

func (w *watermarkMarshalWriter) data(b []byte) {
	w.pieces = append(w.pieces, watermarkMarshalPiece{data: b})
	w.size += int64(len(b))
}
func (w *watermarkMarshalWriter) original(at, size int64) {
	if size > 0 {
		w.pieces = append(w.pieces, watermarkMarshalPiece{at: at, size: size})
		w.size += size
	}
}
func (w *watermarkMarshalWriter) object(value *watermarkMarshalValue, constants bool) {
	w.depth++
	defer func() { w.depth-- }()
	if w.depth > 128 {
		panic("Python marshal rewrite depth limit")
	}
	id := watermarkMarshalIdentity{value, constants}
	if value.kind == '(' && (w.active[watermarkMarshalIdentity{value, !constants}] || (constants && w.active[id])) {
		panic("cannot safely split recursive Python co_consts alias")
	}
	switch value.kind {
	case '0', 'N', 'F', 'T', 'S', '.':
		w.original(value.start, value.end-value.start)
		return
	}
	if ref, ok := w.refs[id]; ok {
		if w.active[id] && (value.kind == 'c' || value.kind == '>' || value.kind == ':') {
			panic("cannot safely rewrite unfinished Python code/frozenset/slice reference")
		}
		w.data(binary.LittleEndian.AppendUint32([]byte{'r'}, ref))
		return
	}
	if len(w.refs) >= 1<<20 {
		panic("Python marshal rewritten reference limit")
	}
	w.refs[id] = uint32(len(w.refs))
	w.active[id] = true
	if constants {
		if value.kind != '(' || value.n > math.MaxInt32-8 {
			panic("Python constant table overflow or invalid type")
		}
		if len(w.offsets) > 65535-8 {
			panic("too many Python watermark slots")
		}
		count := value.n + 8
		if value.n == 0 {
			// CPython creates function.__doc__ from co_consts[0] when it is
			// a string. Empty compiler-generated code (e.g. comprehensions)
			// must not acquire the first watermark string as its docstring.
			// There are no original indices to shift in this case.
			count++
		}
		w.data(binary.LittleEndian.AppendUint32([]byte{'(' | 128}, uint32(count)))
		if value.n == 0 {
			w.data([]byte{'N'})
		}
		for _, edge := range value.children {
			w.object(edge.value, edge.constants)
		}
		for i := 0; i < 8; i++ {
			prefix := strconv.Itoa(len(w.offsets)) + ":" + watermarkSlotLabel(w.random[:], i)
			text := prefix + w.tag + "0000000000000000000000000000000000000000000000000000000000000000"
			if len(text) > 255 {
				panic("Python watermark string too long")
			}
			w.offsets = append(w.offsets, strconv.FormatInt(16+w.size+2+int64(len(prefix)), 10))
			w.data(append([]byte{'z', byte(len(text))}, text...))
		}
	} else {
		w.data([]byte{value.raw | 128})
		cursor := value.start + 1
		for _, edge := range value.children {
			w.original(cursor, edge.start-cursor)
			w.object(edge.value, edge.constants)
			cursor = edge.end
		}
		w.original(cursor, value.end-cursor)
	}
	delete(w.active, id)
}

func preparePythonEntry(file *os.File, size int64, tag string) (edits []watermarkEdit, offsets []string, newSize int64, err error) {
	defer func() {
		if reason := recover(); reason != nil {
			edits, offsets, newSize = nil, nil, 0
			err = fmt.Errorf("cannot watermark compiled Python marshal: %v", reason)
		}
	}()
	if size < 17 || size > math.MaxInt64/2 || len(tag) != 32 {
		return nil, nil, 0, errors.New("invalid pyc size or watermark tag")
	}
	var header [16]byte
	if _, err = file.ReadAt(header[:], 0); err != nil {
		return nil, nil, 0, err
	}
	// pyc format support is independent of the SDK's Python >=3.9 floor.
	version := map[uint16]int{3413: 308, 3425: 309, 3439: 310, 3495: 311, 3531: 312, 3571: 313, 3627: 314}[binary.LittleEndian.Uint16(header[:2])]
	if version == 0 || header[2] != 13 || header[3] != 10 || binary.LittleEndian.Uint32(header[4:8])&^uint32(3) != 0 {
		return nil, nil, 0, errors.New("unsupported pyc header")
	}
	reader := watermarkMarshal{window: watermarkWindow{file: file, size: size}, pos: 16, version: version}
	root := reader.object(false)
	if root.value.kind != 'c' || reader.pos != size || reader.codes == 0 {
		return nil, nil, 0, errors.New("pyc must contain exactly one module code object")
	}
	writer := watermarkMarshalWriter{refs: make(map[watermarkMarshalIdentity]uint32), active: make(map[watermarkMarshalIdentity]bool), tag: tag}
	if _, err = io.ReadFull(rand.Reader, writer.random[:]); err != nil {
		return nil, nil, 0, errors.New("watermark randomness failed")
	}
	defer clear(writer.random[:])
	writer.object(root.value, false)
	if writer.size > math.MaxInt64/2-16 || len(writer.offsets) == 0 {
		return nil, nil, 0, errors.New("watermarked pyc too large or no code constants")
	}
	return []watermarkEdit{{at: 16, remove: size - 16, pieces: writer.pieces}}, writer.offsets, writer.size + 16, nil
}

func preparePythonWatermark(input source, tag string) (source, []watermarkIndexEntry, error) {
	if input.file.Kind != "python" || input.file.Encoding != "tar" || len(tag) != 32 {
		return source{}, nil, invalid
	}
	entries := []watermarkIndexEntry{}
	total := 0
	input.entryEdits = map[string][]watermarkEdit{}
	input.entrySizes = map[string]int64{}
	for i := range input.entries {
		item := &input.entries[i]
		file, e := openSafe(item.path)
		if e != nil {
			return source{}, nil, e
		}
		stat, e := file.Stat()
		if e != nil || !os.SameFile(item.info, stat) || stat.Size() != item.info.Size() || !stat.ModTime().Equal(item.info.ModTime()) {
			file.Close()
			return source{}, nil, errors.New("input changed")
		}
		edits, offsets, size, e := preparePythonEntry(file, stat.Size(), tag)
		file.Close()
		if e != nil {
			return source{}, nil, e
		}
		total += len(offsets)
		if total > 65535 {
			return source{}, nil, errors.New("too many Python watermark slots")
		}
		input.entryEdits[item.name] = edits
		input.entrySizes[item.name] = size
		entries = append(entries, watermarkIndexEntry{Path: []string{item.name}, Offsets: offsets})
	}
	var count counter
	if e := input.writeArchive(&count); e != nil {
		return source{}, nil, e
	}
	input.file.Size = int64(count)
	return input, entries, nil
}

// CreateWatermarkedPython uses no Python runtime: it rewrites compiler-produced
// marshal structure with bounded, reference-preserving edits, never pyc tails.
func CreateWatermarkedPython(input, destination string, p Payload, public []byte) error {
	original, e := inspect("python", "core", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := preparePythonWatermark(original, tag)
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
