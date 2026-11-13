package pack

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
)

const watermarkArchiveLimit = 256 << 20

type watermarkJar struct {
	entries []watermarkJarEntry
	path    []string
}
type watermarkJarEntry struct {
	header                    zip.FileHeader
	data                      []byte
	nested                    *watermarkJar
	poolEnd, poolCount, slots int
}

func javaConstantPool(data []byte) (int, int, error) {
	if len(data) < 10 || binary.BigEndian.Uint32(data) != 0xcafebabe {
		return 0, 0, errors.New("invalid Java class header")
	}
	count := int(binary.BigEndian.Uint16(data[8:10]))
	if count < 1 {
		return 0, 0, errors.New("invalid Java constant pool")
	}
	position := 10
	for i := 1; i < count; i++ {
		if position >= len(data) {
			return 0, 0, errors.New("truncated Java constant pool")
		}
		kind := data[position]
		position++
		size := 0
		switch kind {
		case 1:
			if position+2 > len(data) {
				return 0, 0, errors.New("truncated Java UTF8")
			}
			size = 2 + int(binary.BigEndian.Uint16(data[position:position+2]))
		case 3, 4, 9, 10, 11, 12, 17, 18:
			size = 4
		case 5, 6:
			size = 8
			i++
			if i >= count {
				return 0, 0, errors.New("invalid Java two-slot constant")
			}
		case 7, 8, 16, 19, 20:
			size = 2
		case 15:
			size = 3
		default:
			return 0, 0, errors.New("unsupported Java constant pool tag")
		}
		if size > len(data)-position {
			return 0, 0, errors.New("truncated Java constant pool")
		}
		position += size
	}
	return position, count, nil
}
func readWatermarkJar(data []byte, path []string, depth int, total *int64, count *int, eligible *[]*watermarkJarEntry) (*watermarkJar, error) {
	if depth > 7 || len(data) > watermarkArchiveLimit {
		return nil, errors.New("watermark JAR resource limit")
	}
	zipReader, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return nil, errors.New("invalid watermark JAR")
	}
	jar := &watermarkJar{path: append([]string(nil), path...)}
	seen := map[string]bool{}
	// Allocate once: eligible pointers must remain stable while siblings append.
	jar.entries = make([]watermarkJarEntry, len(zipReader.File))
	for i, file := range zipReader.File {
		*count++
		if *count > 65535 || !safeEntry(strings.TrimSuffix(file.Name, "/")) || seen[file.Name] || file.Mode().Type() != 0 && !file.FileInfo().IsDir() {
			return nil, errors.New("unsafe or duplicate JAR entry")
		}
		seen[file.Name] = true
		upper := strings.ToUpper(file.Name)
		if strings.HasPrefix(upper, "META-INF/") && (strings.HasSuffix(upper, ".SF") || strings.HasSuffix(upper, ".RSA") || strings.HasSuffix(upper, ".DSA") || strings.HasSuffix(upper, ".EC") || strings.HasPrefix(upper, "META-INF/SIG-")) {
			return nil, errors.New("signed JAR cannot be watermarked; remove signing in the build stage")
		}
		if file.UncompressedSize64 > watermarkArchiveLimit || int64(file.UncompressedSize64) > watermarkArchiveLimit-*total {
			return nil, errors.New("watermark JAR expansion limit")
		}
		reader, e := file.Open()
		if e != nil {
			return nil, errors.New("JAR entry unreadable")
		}
		plain, e := io.ReadAll(io.LimitReader(reader, watermarkArchiveLimit-*total+1))
		reader.Close()
		if e != nil || len(plain) > watermarkArchiveLimit-int(*total) || uint64(len(plain)) != file.UncompressedSize64 {
			return nil, errors.New("JAR CRC/size or expansion failure")
		}
		*total += int64(len(plain))
		entry := &jar.entries[i]
		entry.header = file.FileHeader
		entry.data = plain
		if file.FileInfo().IsDir() {
			continue
		}
		if strings.HasSuffix(file.Name, ".jar") {
			entry.nested, e = readWatermarkJar(plain, append(append([]string(nil), path...), file.Name), depth+1, total, count, eligible)
			if e != nil {
				return nil, e
			}
		} else if strings.HasSuffix(file.Name, ".class") {
			entry.poolEnd, entry.poolCount, e = javaConstantPool(plain)
			if e != nil {
				return nil, e
			}
			if entry.poolCount < 65535 {
				*eligible = append(*eligible, entry)
			}
		}
	}
	return jar, nil
}
func writeWatermarkJar(jar *watermarkJar, tag string, descriptors *[]watermarkIndexEntry) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for i := range jar.entries {
		entry := &jar.entries[i]
		data := entry.data
		var e error
		if entry.nested != nil {
			data, e = writeWatermarkJar(entry.nested, tag, descriptors)
			if e != nil {
				writer.Close()
				return nil, e
			}
		}
		if entry.slots > 0 {
			insertion := []byte{}
			offsets := []string{}
			for n := 0; n < entry.slots; n++ {
				offsets = append(offsets, strconv.Itoa(entry.poolEnd+len(insertion)+3))
				insertion = append(insertion, 1, 0, 96)
				insertion = append(insertion, []byte(tag+strings.Repeat("0", 64))...)
			}
			updated := make([]byte, 0, len(data)+len(insertion))
			updated = append(updated, data[:8]...)
			updated = binary.BigEndian.AppendUint16(updated, uint16(entry.poolCount+entry.slots))
			updated = append(updated, data[10:entry.poolEnd]...)
			updated = append(updated, insertion...)
			updated = append(updated, data[entry.poolEnd:]...)
			if !bytes.Equal(updated[10:entry.poolEnd], data[10:entry.poolEnd]) || !bytes.Equal(updated[entry.poolEnd+len(insertion):], data[entry.poolEnd:]) {
				writer.Close()
				return nil, errors.New("unexpected Java bytecode/attribute mutation")
			}
			data = updated
			*descriptors = append(*descriptors, watermarkIndexEntry{Path: append(append([]string(nil), jar.path...), entry.header.Name), Offsets: offsets})
		}
		header := entry.header
		part, e := writer.CreateHeader(&header)
		if e != nil {
			writer.Close()
			return nil, errors.New("watermark JAR rewrite failed")
		}
		if _, e = part.Write(data); e != nil {
			writer.Close()
			return nil, errors.New("watermark JAR rewrite failed")
		}
	}
	if e := writer.Close(); e != nil {
		return nil, errors.New("watermark JAR rewrite failed")
	}
	if output.Len() > watermarkArchiveLimit {
		return nil, errors.New("watermarked JAR too large")
	}
	return output.Bytes(), nil
}
func prepareJavaWatermark(input source, tag string) (source, []watermarkIndexEntry, error) {
	if input.file.Kind != "java" || input.file.Encoding != "raw" || input.info.Size() > watermarkArchiveLimit {
		return source{}, nil, errors.New("invalid or oversized watermark JAR")
	}
	reader, e := input.reader()
	if e != nil {
		return source{}, nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(reader, watermarkArchiveLimit+1))
	reader.Close()
	if e != nil || len(raw) > watermarkArchiveLimit {
		return source{}, nil, errors.New("JAR input unreadable")
	}
	var total int64
	count := 0
	eligible := []*watermarkJarEntry{}
	jar, e := readWatermarkJar(raw, nil, 0, &total, &count, &eligible)
	if e != nil {
		return source{}, nil, e
	}
	if len(eligible) == 0 {
		return source{}, nil, errors.New("no Java class has room for watermark constants")
	}
	for i := len(eligible) - 1; i > 0; i-- {
		pick, e := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if e != nil {
			return source{}, nil, errors.New("watermark randomness failed")
		}
		j := int(pick.Int64())
		eligible[i], eligible[j] = eligible[j], eligible[i]
	}
	for remaining, cursor := 8, 0; remaining > 0; cursor++ {
		if cursor > 8*len(eligible) {
			return source{}, nil, errors.New("Java constant pools have insufficient watermark capacity")
		}
		entry := eligible[cursor%len(eligible)]
		if entry.poolCount+entry.slots >= 65535 {
			continue
		}
		entry.slots++
		remaining--
	}
	descriptors := []watermarkIndexEntry{}
	rewritten, e := writeWatermarkJar(jar, tag, &descriptors)
	if e != nil {
		return source{}, nil, e
	}
	input.generated = rewritten
	input.file.Size = int64(len(rewritten))
	return input, descriptors, nil
}
func CreateWatermarkedJava(input, destination string, p Payload, public []byte) error {
	original, e := inspect("java", "app", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := prepareJavaWatermark(original, tag)
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
