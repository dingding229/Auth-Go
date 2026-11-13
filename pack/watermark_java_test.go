package pack

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type watermarkJavaTestFile struct {
	name string
	data []byte
}

// A Java 8 class with real Code, StackMapTable and SourceFile attributes. The
// branch targets bytecode offset 7; ldc #15 and invokespecial #9 depend on the
// original CP numbering. Long/double entries deliberately consume two indices.
func watermarkJavaTestClass(t *testing.T, name string, count int) ([]byte, int) {
	t.Helper()
	if count < 23 || count > 65535 {
		t.Fatal("invalid fixture constant pool count", count)
	}
	data := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52}
	data = binary.BigEndian.AppendUint16(data, uint16(count))
	utf8 := func(text string) {
		data = append(data, 1)
		data = binary.BigEndian.AppendUint16(data, uint16(len(text)))
		data = append(data, text...)
	}
	utf8(name)                                                          // #1
	data = append(data, 7, 0, 1)                                        // #2 Class
	utf8("java/lang/Object")                                            // #3
	data = append(data, 7, 0, 3)                                        // #4 Class
	utf8("<init>")                                                      // #5
	utf8("()V")                                                         // #6
	utf8("Code")                                                        // #7
	data = append(data, 12, 0, 5, 0, 6)                                 // #8 NameAndType
	data = append(data, 10, 0, 4, 0, 8)                                 // #9 Methodref
	utf8("choose")                                                      // #10
	utf8("(I)I")                                                        // #11
	utf8("StackMapTable")                                               // #12
	utf8("SourceFile")                                                  // #13
	utf8("Main.java")                                                   // #14
	data = append(data, 3, 0x12, 0x34, 0x56, 0x78)                      // #15 Integer
	data = append(data, 4, 0x3f, 0xc0, 0, 0)                            // #16 Float (1.5)
	data = append(data, 5, 1, 2, 3, 4, 5, 6, 7, 8)                      // #17 Long, #18 reserved
	data = append(data, 6, 0x40, 9, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18) // #19 Double, #20 reserved
	utf8("kept")                                                        // #21
	data = append(data, 8, 0, 21)                                       // #22 String
	for i := 23; i < count; i++ {
		utf8("pad")
	}
	poolEnd := len(data)
	data = append(data,
		0, 0x21, 0, 2, 0, 4, // access, this_class, super_class
		0, 0, 0, 0, 0, 2, // interfaces, fields, methods
		0, 1, 0, 5, 0, 6, 0, 1, // public <init>()V, one attribute
		0, 7, 0, 0, 0, 17, // Code, length 17
		0, 1, 0, 1, 0, 0, 0, 5, // stack, locals, code_length
		0x2a, 0xb7, 0, 9, 0xb1, // aload_0; invokespecial #9; return
		0, 0, 0, 0, // no exceptions or nested attributes
		0, 9, 0, 10, 0, 11, 0, 1, // public static choose(I)I
		0, 7, 0, 0, 0, 30, // Code, length 30
		0, 1, 0, 1, 0, 0, 0, 9,
		0x1a, 0x99, 0, 6, 0x12, 15, 0xac, 0x03, 0xac,
		0, 0, 0, 1, // no exceptions, one nested attribute
		0, 12, 0, 0, 0, 3, 0, 1, 7, // StackMapTable: one same_frame at offset 7
		0, 1, 0, 13, 0, 0, 0, 2, 0, 14, // SourceFile: Main.java
	)
	return data, poolEnd
}

func watermarkJavaTestJar(t *testing.T, files ...watermarkJavaTestFile) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range files {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: file.name, Method: zip.Deflate, Comment: "watermark fixture"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func watermarkJavaTestLeaves(t *testing.T, raw []byte, prefix []string, leaves map[string][]byte) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		part, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			t.Fatal(err)
		}
		path := append(append([]string(nil), prefix...), file.Name)
		if strings.HasSuffix(file.Name, ".jar") {
			watermarkJavaTestLeaves(t, data, path, leaves)
		} else {
			key := strings.Join(path, "!")
			if _, exists := leaves[key]; exists {
				t.Fatal("duplicate fixture path", key)
			}
			leaves[key] = data
		}
	}
}

func watermarkJavaTestSource(t *testing.T, raw []byte) (source, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := inspect("java", "app", path)
	if err != nil {
		t.Fatal(err)
	}
	return input, path
}

func watermarkJavaTestAppendOnly(t *testing.T, before, after []byte, slots int, offsets []string, tag string) {
	t.Helper()
	oldEnd, oldCount, err := javaConstantPool(before)
	if err != nil {
		t.Fatal(err)
	}
	newEnd, newCount, err := javaConstantPool(after)
	if err != nil {
		t.Fatal(err)
	}
	if newCount != oldCount+slots || newEnd != oldEnd+99*slots || len(after) != len(before)+99*slots {
		t.Fatalf("not a strict CP append: count %d -> %d, end %d -> %d, slots %d", oldCount, newCount, oldEnd, newEnd, slots)
	}
	if !bytes.Equal(before[:8], after[:8]) || !bytes.Equal(before[10:oldEnd], after[10:oldEnd]) {
		t.Fatal("existing CP entries, numeric bits, indices or class version changed")
	}
	if !bytes.Equal(before[oldEnd:], after[newEnd:]) {
		t.Fatal("class body changed: bytecode, StackMapTable and all attributes must be identical")
	}
	if len(offsets) != slots {
		t.Fatalf("index has %d offsets, want %d", len(offsets), slots)
	}
	want := append([]byte{1, 0, 96}, []byte(tag+strings.Repeat("0", 64))...)
	for i, offset := range offsets {
		start := oldEnd + 99*i
		if offset != strconv.Itoa(start+3) || !bytes.Equal(after[start:start+99], want) {
			t.Fatal("appended entry is not the indexed 96-byte CONSTANT_Utf8", offset)
		}
	}
}

func TestJavaWatermarkStrictAppendOnly(t *testing.T) {
	for _, classes := range []int{1, 3, 8, 10} {
		t.Run(fmt.Sprintf("classes-%d", classes), func(t *testing.T) {
			files := []watermarkJavaTestFile{{"META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\n\r\n")}, {"config.bin", []byte{0, 1, 2, 0xff}}}
			for i := 0; i < classes; i++ {
				name := fmt.Sprintf("watermark/Class%d", i)
				data, end := watermarkJavaTestClass(t, name, 23)
				gotEnd, count, err := javaConstantPool(data)
				if err != nil || gotEnd != end || count != 23 {
					t.Fatalf("fixture CP (including long/double): end %d, count %d, err %v", gotEnd, count, err)
				}
				files = append(files, watermarkJavaTestFile{name + ".class", data})
			}
			raw := watermarkJavaTestJar(t, files...)
			input, path := watermarkJavaTestSource(t, raw)
			tag := strings.Repeat("a", 32)
			prepared, entries, err := prepareJavaWatermark(input, tag)
			if err != nil {
				t.Fatal(err)
			}
			before, after := map[string][]byte{}, map[string][]byte{}
			watermarkJavaTestLeaves(t, raw, nil, before)
			watermarkJavaTestLeaves(t, prepared.generated, nil, after)
			if len(before) != len(after) || prepared.file.Size != int64(len(prepared.generated)) || prepared.file.MainClass != input.file.MainClass {
				t.Fatal("JAR contents or manifest metadata changed")
			}
			indexed := map[string][]string{}
			total := 0
			for _, entry := range entries {
				if len(entry.Path) != 1 || len(entry.Offsets) == 0 || indexed[entry.Path[0]] != nil {
					t.Fatal("invalid or duplicate class descriptor", entry)
				}
				if _, ok := before[entry.Path[0]]; !ok || !strings.HasSuffix(entry.Path[0], ".class") {
					t.Fatal("descriptor does not identify an existing business class", entry)
				}
				indexed[entry.Path[0]] = entry.Offsets
				total += len(entry.Offsets)
			}
			if total != 8 || len(entries) != min(classes, 8) {
				t.Fatalf("want 8 slots spread across min(classes,8), got %d slots in %d classes", total, len(entries))
			}
			for name, original := range before {
				if offsets := indexed[name]; offsets != nil {
					watermarkJavaTestAppendOnly(t, original, after[name], len(offsets), offsets, tag)
				} else if !bytes.Equal(original, after[name]) {
					t.Fatal("unselected class or resource changed", name)
				}
			}
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(unchanged, raw) {
				t.Fatal("original JAR overwritten", err)
			}
		})
	}
}

func TestJavaWatermarkRecursiveNestedJars(t *testing.T) {
	class, _ := watermarkJavaTestClass(t, "watermark/Main", 23)
	deepFiles := []watermarkJavaTestFile{{"deep.txt", []byte("deep resource")}}
	for i := 0; i < 5; i++ {
		data, _ := watermarkJavaTestClass(t, fmt.Sprintf("watermark/Deep%d", i), 23)
		deepFiles = append(deepFiles, watermarkJavaTestFile{fmt.Sprintf("watermark/Deep%d.class", i), data})
	}
	deep := watermarkJavaTestJar(t, deepFiles...)
	library := watermarkJavaTestJar(t, watermarkJavaTestFile{"watermark/Main.class", class}, watermarkJavaTestFile{"lib/deep.jar", deep}, watermarkJavaTestFile{"lib.txt", []byte("library resource")})
	sibling := watermarkJavaTestJar(t, watermarkJavaTestFile{"watermark/Main.class", class}, watermarkJavaTestFile{"sibling.txt", []byte("sibling resource")})
	raw := watermarkJavaTestJar(t, watermarkJavaTestFile{"BOOT-INF/classes/watermark/Main.class", class}, watermarkJavaTestFile{"BOOT-INF/lib/first.jar", library}, watermarkJavaTestFile{"BOOT-INF/lib/second.jar", sibling}, watermarkJavaTestFile{"application.properties", []byte("key=value\n")})
	input, path := watermarkJavaTestSource(t, raw)
	tag := strings.Repeat("b", 32)
	prepared, entries, err := prepareJavaWatermark(input, tag)
	if err != nil {
		t.Fatal(err)
	}
	before, after := map[string][]byte{}, map[string][]byte{}
	watermarkJavaTestLeaves(t, raw, nil, before)
	watermarkJavaTestLeaves(t, prepared.generated, nil, after)
	if len(before) != len(after) || len(entries) != 8 {
		t.Fatal("recursive classes/resources missing or not indexed")
	}
	indexed := map[string]bool{}
	for _, entry := range entries {
		name := strings.Join(entry.Path, "!")
		original, ok := before[name]
		if !ok || !strings.HasSuffix(name, ".class") || indexed[name] {
			t.Fatal("wrong/aliased nested descriptor path", entry.Path)
		}
		indexed[name] = true
		watermarkJavaTestAppendOnly(t, original, after[name], 1, entry.Offsets, tag)
	}
	for name, original := range before {
		if strings.HasSuffix(name, ".class") {
			if !indexed[name] {
				t.Fatal("nested class skipped", name)
			}
		} else if !bytes.Equal(original, after[name]) {
			t.Fatal("nested resource changed", name)
		}
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("original nested JAR overwritten", err)
	}
}

func TestJavaWatermarkRejectsSignedJarsAtEveryLevel(t *testing.T) {
	class, _ := watermarkJavaTestClass(t, "watermark/Main", 23)
	for _, signature := range []string{"META-INF/KEY.SF", "META-INF/KEY.RSA", "META-INF/KEY.DSA", "META-INF/KEY.EC", "META-INF/SIG-CUSTOM", "meta-inf/key.sF"} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested-%t", signature, nested), func(t *testing.T) {
				files := []watermarkJavaTestFile{{"watermark/Main.class", class}}
				if nested {
					leaf := watermarkJavaTestJar(t, watermarkJavaTestFile{signature, []byte("signature")})
					middle := watermarkJavaTestJar(t, watermarkJavaTestFile{"lib/signed.jar", leaf})
					files = append(files, watermarkJavaTestFile{"BOOT-INF/lib/middle.jar", middle})
				} else {
					files = append(files, watermarkJavaTestFile{signature, []byte("signature")})
				}
				raw := watermarkJavaTestJar(t, files...)
				watermarkJavaTestRefusal(t, raw, "signed JAR cannot be watermarked; remove signing in the build stage")
			})
		}
	}
}

func watermarkJavaTestRefusal(t *testing.T, raw []byte, reason string) {
	t.Helper()
	input, path := watermarkJavaTestSource(t, raw)
	prepared, entries, err := prepareJavaWatermark(input, strings.Repeat("c", 32))
	if err == nil || !strings.Contains(err.Error(), reason) || prepared.generated != nil || len(entries) != 0 {
		t.Fatalf("want refusal %q without output/index, got %v", reason, err)
	}
	destination := filepath.Join(t.TempDir(), "unpublished")
	err = CreateWatermarkedJava(path, destination, Payload{}, bytes.Repeat([]byte{7}, 32))
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("public packer did not propagate refusal %q: %v", reason, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("refused JAR published output", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("refused JAR changed input", err)
	}
}

func TestJavaWatermarkConstantPoolCapacity(t *testing.T) {
	for _, test := range []struct {
		name   string
		counts []int
		reason string
	}{
		{"no-classes", nil, "no Java class has room"},
		{"full-only", []int{65535}, "no Java class has room"},
		{"one-slot-is-not-eight", []int{65534}, "insufficient watermark capacity"},
		{"seven-slots-is-not-eight", []int{65528}, "insufficient watermark capacity"},
		{"full-plus-seven-slots", []int{65535, 65528}, "insufficient watermark capacity"},
		{"exact-eight-slots", []int{65527}, ""},
		{"full-skipped", []int{65535, 23}, ""},
		{"eight-nearly-full-classes", []int{65534, 65534, 65534, 65534, 65534, 65534, 65534, 65534}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := []watermarkJavaTestFile{{"resource.txt", []byte("not a class")}}
			for i, count := range test.counts {
				name := fmt.Sprintf("watermark/Class%d", i)
				data, _ := watermarkJavaTestClass(t, name, count)
				files = append(files, watermarkJavaTestFile{name + ".class", data})
			}
			raw := watermarkJavaTestJar(t, files...)
			if test.reason != "" {
				watermarkJavaTestRefusal(t, raw, test.reason)
				return
			}
			input, path := watermarkJavaTestSource(t, raw)
			tag := strings.Repeat("d", 32)
			prepared, entries, err := prepareJavaWatermark(input, tag)
			if err != nil {
				t.Fatal(err)
			}
			before, after := map[string][]byte{}, map[string][]byte{}
			watermarkJavaTestLeaves(t, raw, nil, before)
			watermarkJavaTestLeaves(t, prepared.generated, nil, after)
			indexed := map[string]bool{}
			total := 0
			for _, entry := range entries {
				if len(entry.Path) != 1 || indexed[entry.Path[0]] {
					t.Fatal("bad capacity descriptor", entry)
				}
				name := entry.Path[0]
				original, ok := before[name]
				if !ok || binary.BigEndian.Uint16(original[8:10]) == 65535 {
					t.Fatal("full CP was not skipped", name)
				}
				indexed[name] = true
				total += len(entry.Offsets)
				watermarkJavaTestAppendOnly(t, original, after[name], len(entry.Offsets), entry.Offsets, tag)
			}
			if total != 8 || len(before) != len(after) {
				t.Fatal("capacity boundary did not preserve all files and exactly eight slots", total)
			}
			for name, original := range before {
				if !indexed[name] && !bytes.Equal(original, after[name]) {
					t.Fatal("skipped full class or resource changed", name)
				}
			}
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(unchanged, raw) {
				t.Fatal("capacity handling overwrote input", err)
			}
		})
	}
}
