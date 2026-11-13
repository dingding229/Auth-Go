package pack

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

func prepareDotnetWatermark(input source, tag string) (source, []watermarkIndexEntry, error) {
	if input.file.Kind != "dotnet" || len(input.entries) == 0 {
		return source{}, nil, invalid
	}
	main := input.entries[0]
	file, e := openSafe(main.path)
	if e != nil {
		return source{}, nil, e
	}
	defer file.Close()
	stat, e := file.Stat()
	if e != nil || !os.SameFile(main.info, stat) || stat.Size() != main.info.Size() || !stat.ModTime().Equal(main.info.ModTime()) {
		return source{}, nil, errors.New("input changed")
	}
	image, e := pe.NewFile(file)
	if e != nil {
		return source{}, nil, errors.New("watermark requires managed PE")
	}
	defer image.Close()
	var cor pe.DataDirectory
	switch header := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		cor = header.DataDirectory[14]
	case *pe.OptionalHeader64:
		cor = header.DataDirectory[14]
	default:
		return source{}, nil, invalid
	}
	corOK := false
	for _, section := range image.Sections {
		if cor.VirtualAddress < section.VirtualAddress || uint64(cor.VirtualAddress-section.VirtualAddress)+72 > uint64(section.Size) {
			continue
		}
		var header [72]byte
		if _, e = section.ReadAt(header[:], int64(cor.VirtualAddress-section.VirtualAddress)); e != nil {
			return source{}, nil, invalid
		}
		// IL-only, no native entrypoint or ReadyToRun managed-native directory.
		flags := binary.LittleEndian.Uint32(header[16:20])
		if flags&0x11 != 1 || binary.LittleEndian.Uint32(header[64:68]) != 0 || binary.LittleEndian.Uint32(header[68:72]) != 0 {
			return source{}, nil, errors.New("watermark does not support native, mixed, AOT or ReadyToRun assemblies")
		}
		corOK = true
	}
	if !corOK {
		return source{}, nil, invalid
	}
	mapped := func(at int64) bool {
		for _, section := range image.Sections {
			if section.Characteristics&0x02000000 != 0 || uint64(section.Offset) > uint64(stat.Size()) || uint64(section.Size) > uint64(stat.Size())-uint64(section.Offset) {
				continue
			}
			if at >= int64(section.Offset) && at-int64(section.Offset) <= int64(section.Size) && 96 <= int64(section.Size)-(at-int64(section.Offset)) {
				return true
			}
		}
		return false
	}
	replacement := []byte(tag + strings.Repeat("0", 64))
	counts := make([]int, 8)
	edits := []watermarkEdit{}
	buffer := make([]byte, 1<<20)
	carry := []byte{}
	var position, next int64
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			data := append(carry, buffer[:n]...)
			base := position - int64(len(carry))
			for i := 0; i+96 <= len(data); i++ {
				at := base + int64(i)
				if at < next || data[i] != 'c' || !mapped(at) {
					continue
				}
				for marker := 0; marker < 8; marker++ {
					expected := watermarkPlaceholder(marker)
					if bytes.Equal(data[i:i+96], expected) {
						edits = append(edits, watermarkEdit{at: at, remove: 96, insert: replacement, expected: expected})
						counts[marker]++
						break
					}
				}
			}
			position += int64(n)
			if position >= 95 {
				next = position - 95
			}
			start := len(data) - 95
			if start < 0 {
				start = 0
			}
			carry = append([]byte(nil), data[start:]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return source{}, nil, errors.New("assembly watermark read failed")
		}
	}
	for _, n := range counts {
		if n == 0 {
			return source{}, nil, errors.New("missing C# watermark slots: include AuthGo.Watermark.cs; trim, AOT and single-file publishing are unsupported")
		}
	}
	if len(edits) > 65535 {
		return source{}, nil, errors.New("too many assembly watermark slots")
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].at < edits[j].at })
	offsets := make([]string, len(edits))
	for i, edit := range edits {
		if i > 0 && edits[i-1].at+96 > edit.at {
			return source{}, nil, errors.New("overlapping assembly watermark slots")
		}
		offsets[i] = strconv.FormatInt(edit.at, 10)
	}
	input.entryEdits = map[string][]watermarkEdit{main.name: edits}
	input.entrySizes = map[string]int64{main.name: stat.Size()}
	return input, []watermarkIndexEntry{{Path: []string{main.name}, Offsets: offsets}}, nil
}
func CreateWatermarkedDotnet(input, destination string, p Payload, public []byte) error {
	original, e := inspect("dotnet", "app", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := prepareDotnetWatermark(original, tag)
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
