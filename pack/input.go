package pack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// openSafe traverses every component using directory FDs and O_NOFOLLOW.
// Targets are Linux (amd64/arm64); never follow a symlink, even inside the root.
func openSafe(p string) (*os.File, error) {
	abs, e := filepath.Abs(p)
	if e != nil {
		return nil, errors.New("invalid input path")
	}
	dir, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	if abs == "/" {
		return os.NewFile(uintptr(dir), abs), nil
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for i, s := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(dir, s, flags, 0)
		syscall.Close(dir)
		if err != nil {
			return nil, errors.New("input unavailable or symlink")
		}
		dir = next
	}
	return os.NewFile(uintptr(dir), abs), nil
}
func safeEntry(s string) bool {
	return utf8.ValidString(s) && s != "" && !strings.ContainsAny(s, "\\\x00:") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../")
}
func strictJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return invalid
	}
	// Reject duplicate/unknown/case-aliased keys and missing required fields,
	// unlike encoding/json's otherwise case-insensitive struct field matching.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(reflect.Type, int) error
	value = func(typ reflect.Type, depth int) error {
		if depth > 64 {
			return invalid
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if token == nil && typ != nil && typ.Kind() != reflect.Slice && typ.Kind() != reflect.Map && typ.Kind() != reflect.Interface {
			return invalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			fields := map[string]reflect.StructField{}
			if typ != nil && typ.Kind() == reflect.Struct {
				for i := 0; i < typ.NumField(); i++ {
					f := typ.Field(i)
					fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f
				}
			}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return invalid
				}
				seen[name] = true
				var child reflect.Type
				if typ != nil && typ.Kind() == reflect.Struct {
					f, ok := fields[name]
					if !ok {
						return invalid
					}
					child = f.Type
				}
				if e = value(child, depth+1); e != nil {
					return e
				}
			}
			for name, f := range fields {
				if !seen[name] && !strings.Contains(f.Tag.Get("json"), ",omitempty") {
					return invalid
				}
			}
		case '[':
			var child reflect.Type
			if typ != nil && typ.Kind() == reflect.Slice {
				child = typ.Elem()
			}
			for d.More() {
				if e = value(child, depth+1); e != nil {
					return e
				}
			}
		default:
			return invalid
		}
		_, e = d.Token()
		return e
	}
	if e := value(reflect.TypeOf(out).Elem(), 0); e != nil {
		return invalid
	}
	if _, e := d.Token(); e != io.EOF {
		return invalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return invalid
	}
	return nil
}
func validateConfig(s, app string) error {
	if len(s) > 32768 || !strings.HasPrefix(s, "authgo2.") {
		return invalid
	}
	raw, e := b64.DecodeString(strings.TrimPrefix(s, "authgo2."))
	if e != nil {
		return invalid
	}
	var c struct {
		URL        string `json:"url"`
		AppKey     string `json:"app_key"`
		AppSecret  string `json:"app_secret"`
		PublicKey  string `json:"public_key"`
		GatewayKey string `json:"gateway_key"`
	}
	if strictJSON(raw, &c) != nil || c.AppKey != app || c.AppSecret == "" {
		return invalid
	}
	https := func(s string) bool {
		u, e := url.Parse(s)
		return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
	}
	if !https(c.URL) {
		return invalid
	}
	pub, e := base64.StdEncoding.Strict().DecodeString(c.PublicKey)
	if e != nil || len(pub) != 32 {
		return invalid
	}
	gateway, e := b64.DecodeString(c.GatewayKey)
	if e != nil || len(gateway) != 32 {
		return invalid
	}
	return nil
}

type source struct {
	entryEdits map[string][]watermarkEdit
	entrySizes map[string]int64
	insertAt   int64
	inserted   []byte
	generated  []byte
	patches    []watermarkBytePatch
	file       File
	path       string
	entries    []entry
	info       os.FileInfo
}
type entry struct {
	name, path string
	info       os.FileInfo
}

func inspect(kind, name, p string) (source, error) {
	s := source{file: File{Name: name, Kind: kind, ChunkSize: ChunkSize, Encoding: "raw"}, path: p}
	if !nameRE.MatchString(name) || len(name) > 128 {
		return s, errors.New("invalid content name")
	}
	f, e := openSafe(p)
	if e != nil {
		return s, e
	}
	defer f.Close()
	s.info, e = f.Stat()
	if e != nil {
		return s, e
	}
	if kind == "python" || kind == "php" {
		if !s.info.IsDir() {
			return s, errors.New("content must be a directory")
		}
		s.file.Encoding = "tar"
		e = filepath.WalkDir(p, func(pth string, d os.DirEntry, err error) error {
			if err != nil {
				return errors.New("directory unreadable")
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("symlinks are not allowed")
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return errors.New("special files are not allowed")
			}
			ext := strings.ToLower(filepath.Ext(pth))
			if kind == "python" && (ext == ".so" || ext == ".pyd") {
				return errors.New("Python native extensions are not supported")
			}
			if kind == "python" && ext == ".py" {
				return errors.New("Python input must be precompiled: remove .py sources from the release staging directory")
			}
			wanted := kind == "python" && ext == ".pyc" || kind == "php" && ext == ".php"
			if !wanted {
				return nil
			}
			rel, _ := filepath.Rel(p, pth)
			rel = filepath.ToSlash(rel)
			if !safeEntry(rel) {
				return errors.New("unsafe archive entry")
			}
			file, e := openSafe(pth)
			if e != nil {
				return e
			}
			defer file.Close()
			st, e := file.Stat()
			if e != nil || !st.Mode().IsRegular() {
				return errors.New("invalid source file")
			}
			if kind == "python" {
				var hdr [16]byte
				if _, e = io.ReadFull(file, hdr[:]); e != nil || hdr[2] != 13 || hdr[3] != 10 {
					return errors.New("invalid pyc header")
				}
				v := map[uint16]string{3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11", 3531: "3.12", 3571: "3.13", 3627: "3.14"}[binary.LittleEndian.Uint16(hdr[:2])]
				if v == "" || binary.LittleEndian.Uint32(hdr[4:8])&^uint32(3) != 0 {
					return errors.New("unsupported Python bytecode version or flags")
				}
				if s.file.PythonVersion != "" && s.file.PythonVersion != v {
					return errors.New("mixed Python bytecode versions")
				}
				s.file.PythonVersion = v
			}
			s.entries = append(s.entries, entry{rel, pth, st})
			return nil
		})
		if e != nil {
			return s, e
		}
		if len(s.entries) == 0 {
			return s, errors.New("directory has no supported code files")
		}
		sort.Slice(s.entries, func(i, j int) bool { return s.entries[i].name < s.entries[j].name })
		var count counter
		if e = s.writeArchive(&count); e != nil {
			return s, e
		}
		s.file.Size = int64(count)
		return s, nil
	}
	if !s.info.Mode().IsRegular() {
		return s, errors.New("content must be a regular file")
	}
	s.file.Size = s.info.Size()
	switch kind {
	case "protect":
		ef, e := elf.NewFile(f)
		if e != nil || ef.Class != elf.ELFCLASS64 || ef.Data != elf.ELFDATA2LSB || (ef.Type != elf.ET_EXEC && ef.Type != elf.ET_DYN) || s.info.Mode()&0111 == 0 {
			return s, errors.New("protect requires an executable ELF64")
		}
		executable := false
		for _, seg := range ef.Progs {
			if seg.Type == elf.PT_LOAD && seg.Flags&elf.PF_X != 0 && seg.Filesz <= uint64(s.info.Size()) && seg.Off <= uint64(s.info.Size())-seg.Filesz && ef.Entry >= seg.Vaddr && ef.Entry-seg.Vaddr < seg.Memsz {
				executable = true
			}
		}
		if !executable {
			return s, errors.New("ELF has no executable entry segment")
		}
		switch ef.Machine {
		case elf.EM_X86_64:
			s.file.Architecture = "amd64"
		case elf.EM_AARCH64:
			s.file.Architecture = "arm64"
		default:
			return s, errors.New("unsupported ELF architecture")
		}
	case "node":
		if filepath.Ext(p) != ".cjs" && filepath.Ext(p) != ".js" {
			return s, errors.New("node requires CommonJS .cjs or .js")
		}
		// Conservative streaming lexical scan, with bounded overlap for tokens.
		if e = checkNode(f); e != nil {
			return s, e
		}
	case "java":
		z, e := zip.NewReader(f, s.info.Size())
		if e != nil {
			return s, errors.New("java requires a jar")
		}
		seen := map[string]bool{}
		for _, zf := range z.File {
			n := strings.TrimSuffix(zf.Name, "/")
			if !safeEntry(n) || seen[n] || (!zf.Mode().IsRegular() && !zf.Mode().IsDir()) {
				return s, errors.New("unsafe jar entry")
			}
			seen[n] = true
			if strings.EqualFold(zf.Name, "META-INF/MANIFEST.MF") {
				if zf.UncompressedSize64 > 1<<20 {
					return s, errors.New("jar manifest too large")
				}
				r, e := zf.Open()
				if e != nil {
					return s, invalid
				}
				b, e := io.ReadAll(io.LimitReader(r, (1<<20)+1))
				r.Close()
				if e != nil || len(b) > 1<<20 {
					return s, invalid
				}
				text := strings.ReplaceAll(string(b), "\r\n", "\n")
				text = strings.ReplaceAll(text, "\n ", "")
				for _, line := range strings.Split(strings.SplitN(text, "\n\n", 2)[0], "\n") {
					if strings.HasPrefix(line, "Main-Class: ") {
						s.file.MainClass = strings.TrimPrefix(line, "Main-Class: ")
					}
				}
			}
		}
	case "dotnet":
		pf, e := pe.NewFile(f)
		if e != nil {
			return s, errors.New("dotnet requires a managed PE assembly")
		}
		var dir pe.DataDirectory
		switch h := pf.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			dir = h.DataDirectory[14]
		case *pe.OptionalHeader64:
			dir = h.DataDirectory[14]
		default:
			return s, invalid
		}
		valid := false
		for _, sec := range pf.Sections {
			if dir.VirtualAddress >= sec.VirtualAddress && uint64(dir.VirtualAddress)+72 <= uint64(sec.VirtualAddress)+uint64(sec.Size) {
				var h [72]byte
				_, e = sec.ReadAt(h[:], int64(dir.VirtualAddress-sec.VirtualAddress))
				valid = e == nil && dir.Size >= 72 && binary.LittleEndian.Uint32(h[:4]) >= 72 && binary.LittleEndian.Uint32(h[16:20])&0x11 == 1
				if valid {
					rva := binary.LittleEndian.Uint32(h[8:12])
					valid = false
					for _, md := range pf.Sections {
						if rva >= md.VirtualAddress && uint64(rva)+4 <= uint64(md.VirtualAddress)+uint64(md.Size) {
							var magic [4]byte
							_, err := md.ReadAt(magic[:], int64(rva-md.VirtualAddress))
							valid = err == nil && string(magic[:]) == "BSJB"
						}
					}
				}
			}
		}
		if !valid {
			return s, errors.New("native or mixed-mode assemblies are not supported")
		}
		s.file.Encoding = "tar"
		s.entries = []entry{{filepath.Base(p), p, s.info}}
		deps := strings.TrimSuffix(p, filepath.Ext(p)) + ".deps.json"
		if _, err := os.Lstat(deps); err == nil {
			df, err := openSafe(deps)
			if err != nil {
				return s, err
			}
			st, err := df.Stat()
			if err != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
				df.Close()
				return s, errors.New("invalid deps.json")
			}
			data, err := io.ReadAll(io.LimitReader(df, (8<<20)+1))
			df.Close()
			var obj map[string]any
			if err != nil || strictJSON(data, &obj) != nil || obj == nil || hasNative(obj) {
				return s, errors.New("invalid or native deps.json")
			}
			s.entries = append(s.entries, entry{filepath.Base(deps), deps, st})
		} else if !os.IsNotExist(err) {
			return s, errors.New("deps.json unreadable")
		}
		var count counter
		if e = s.writeArchive(&count); e != nil {
			return s, e
		}
		s.file.Size = int64(count)
	default:
		return s, errors.New("unsupported content type")
	}
	return s, nil
}

var nativeRequire = regexp.MustCompile(`(?s)require\s*\(\s*['"][^'"\r\n]*\.node['"]`)
var esmToken = regexp.MustCompile(`\b(import|export)\s`)

func checkNode(r io.Reader) error {
	buf := make([]byte, 65536)
	tail := ""
	for {
		n, e := r.Read(buf)
		text := tail + string(buf[:n])
		if nativeRequire.MatchString(text) || strings.Contains(text, ".node") || esmToken.MatchString(text) {
			return errors.New("ESM and native Node modules are not supported")
		}
		if len(text) > 4096 {
			tail = text[len(text)-4096:]
		} else {
			tail = text
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return errors.New("node input unreadable")
		}
	}
}

type counter int64

func (c *counter) Write(b []byte) (int, error) { *c += counter(len(b)); return len(b), nil }
func (s source) writeArchive(w io.Writer) error {
	tw := tar.NewWriter(w)
	for _, en := range s.entries {
		f, e := openSafe(en.path)
		if e != nil {
			return e
		}
		st, e := f.Stat()
		if e != nil || !os.SameFile(en.info, st) || st.Size() != en.info.Size() || !st.ModTime().Equal(en.info.ModTime()) {
			f.Close()
			return errors.New("input changed")
		}
		size := st.Size()
		var reader io.Reader = f
		if edits, ok := s.entryEdits[en.name]; ok {
			size = s.entrySizes[en.name]
			reader, e = watermarkEditedReader(f, st.Size(), edits)
			if e != nil {
				f.Close()
				return e
			}
		}
		h := &tar.Header{Name: en.name, Mode: 0600, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if e = tw.WriteHeader(h); e == nil {
			_, e = io.CopyN(tw, reader, size)
		}
		f.Close()
		if e != nil {
			return errors.New("archive write failed")
		}
	}
	return tw.Close()
}
func (s source) reader() (io.ReadCloser, error) {
	if s.generated != nil {
		return io.NopCloser(bytes.NewReader(s.generated)), nil
	}
	if s.file.Encoding == "raw" {
		f, e := openSafe(s.path)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || !os.SameFile(s.info, st) || st.Size() != s.info.Size() || !st.ModTime().Equal(s.info.ModTime()) {
			f.Close()
			return nil, errors.New("input changed")
		}
		if len(s.inserted) > 0 {
			return &watermarkReadCloser{Reader: io.MultiReader(io.NewSectionReader(f, 0, s.insertAt), bytes.NewReader(s.inserted), io.NewSectionReader(f, s.insertAt, s.info.Size()-s.insertAt)), Closer: f}, nil
		}
		if len(s.patches) > 0 {
			return &watermarkPatchReader{ReadCloser: f, patches: s.patches}, nil
		}
		return f, nil
	}
	r, w := io.Pipe()
	go func() { w.CloseWithError(s.writeArchive(w)) }()
	return r, nil
}

func hasNative(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "native" || hasNative(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if hasNative(v) {
				return true
			}
		}
	case string:
		return x == "native"
	}
	return false
}

// JSON decoders disagree on isolated UTF-16 surrogate escapes. Reject them
// instead of letting encoding/json silently turn them into U+FFFD.
func validUnicodeEscapes(raw []byte) bool {
	inside := false
	for i := 0; i < len(raw); {
		if raw[i] == '"' {
			inside = !inside
			i++
			continue
		}
		if !inside || raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			return false
		}
		if raw[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(raw) {
			return false
		}
		unit, e := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if e != nil {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 12
			continue
		}
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
