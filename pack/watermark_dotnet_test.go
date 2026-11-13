package pack

import (
	"archive/tar"
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

// Extend the existing structural PE fixture, not a runtime-loadable assembly.
// Slots reside in a readable, non-discardable section, away from the CLR header
// and metadata magic. No .NET compiler or runtime is needed for these unit tests.
func watermarkDotnetTestImage(firstSlot int) ([]byte, []int) {
	base := managedPE()
	size := (firstSlot + 7*128 + 96 + 511) / 512 * 512
	image := make([]byte, size)
	copy(image, base)
	binary.LittleEndian.PutUint32(image[376+8:], uint32(size-512))
	binary.LittleEndian.PutUint32(image[376+16:], uint32(size-512))
	binary.LittleEndian.PutUint32(image[376+36:], 0x40000040)
	offsets := make([]int, 8)
	for i := range offsets {
		offsets[i] = firstSlot + 128*i
		copy(image[offsets[i]:], watermarkPlaceholder(i))
	}
	return image, offsets
}

func watermarkDotnetTestFile(t *testing.T, image []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "App.dll")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDotnetWatermarkSameLengthMappedEdits(t *testing.T) {
	for _, firstSlot := range []int{768, (1 << 20) - 40} {
		t.Run(fmt.Sprintf("first-slot-%d", firstSlot), func(t *testing.T) {
			original, offsets := watermarkDotnetTestImage(firstSlot)
			path := watermarkDotnetTestFile(t, original)
			deps := []byte(`{"runtimeTarget":{"name":"test"}}`)
			if err := os.WriteFile(strings.TrimSuffix(path, ".dll")+".deps.json", deps, 0600); err != nil {
				t.Fatal(err)
			}
			input, err := inspect("dotnet", "app", path)
			if err != nil {
				t.Fatal(err)
			}
			tag := strings.Repeat("a", 32)
			prepared, entries, err := prepareDotnetWatermark(input, tag)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || len(entries[0].Path) != 1 || entries[0].Path[0] != "App.dll" || len(entries[0].Offsets) != 8 {
				t.Fatal("invalid assembly watermark index", entries)
			}
			if prepared.file.Size != input.file.Size || prepared.entrySizes["App.dll"] != int64(len(original)) || len(prepared.entryEdits) != 1 {
				t.Fatal("watermark changed assembly/archive size or edited dependencies")
			}
			edits := prepared.entryEdits["App.dll"]
			if len(edits) != 8 {
				t.Fatal("not all eight distinct markers patched", len(edits))
			}
			want := append([]byte(nil), original...)
			replacement := []byte(tag + strings.Repeat("0", 64))
			for i, offset := range offsets {
				if entries[0].Offsets[i] != strconv.Itoa(offset) || edits[i].at != int64(offset) || edits[i].remove != 96 || !bytes.Equal(edits[i].expected, watermarkPlaceholder(i)) || !bytes.Equal(edits[i].insert, replacement) {
					t.Fatal("wrong sorted offset or non-length-preserving edit", i)
				}
				copy(want[offset:offset+96], replacement)
			}
			reader, err := prepared.reader()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			archive := tar.NewReader(reader)
			seen := map[string]bool{}
			for {
				header, err := archive.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(archive)
				if err != nil {
					t.Fatal(err)
				}
				if seen[header.Name] {
					t.Fatal("duplicate output entry", header.Name)
				}
				seen[header.Name] = true
				switch header.Name {
				case "App.dll":
					if header.Size != int64(len(original)) || !bytes.Equal(data, want) {
						t.Fatal("assembly changed beyond the eight marker spans (including PE/CLR headers or metadata)")
					}
				case "App.deps.json":
					if !bytes.Equal(data, deps) {
						t.Fatal("dependency metadata changed")
					}
				default:
					t.Fatal("unexpected output entry", header.Name)
				}
			}
			if len(seen) != 2 || !seen["App.dll"] || !seen["App.deps.json"] {
				t.Fatal("assembly or dependency missing from archive")
			}
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(unchanged, original) {
				t.Fatal("original assembly overwritten", err)
			}
		})
	}
}

func TestDotnetWatermarkMissingMarkersExplainsUnsupportedPublishModes(t *testing.T) {
	// Missing/corrupted markers model the observable failure after omission or
	// trimming; they do not establish that arbitrary trim/single-file builds can
	// be recognized when every marker survives.
	tests := []struct {
		name   string
		mutate func([]byte, []int)
	}{
		{"all-absent", func(image []byte, offsets []int) {
			for _, offset := range offsets {
				clear(image[offset : offset+96])
			}
		}},
		{"eight-copies-of-one-marker", func(image []byte, offsets []int) {
			for _, offset := range offsets {
				copy(image[offset:], watermarkPlaceholder(0))
			}
		}},
		{"corrupted-last-byte", func(image []byte, offsets []int) {
			image[offsets[7]+95] = 'X'
		}},
		{"overlay-only", func(image []byte, offsets []int) {
			binary.LittleEndian.PutUint32(image[376+8:], 256)
			binary.LittleEndian.PutUint32(image[376+16:], 256)
		}},
		{"discardable-section", func(image []byte, offsets []int) {
			binary.LittleEndian.PutUint32(image[376+36:], 0x42000040)
		}},
		{"last-marker-straddles-section-end", func(image []byte, offsets []int) {
			binary.LittleEndian.PutUint32(image[376+16:], uint32(offsets[7]+95-512))
		}},
	}
	for marker := 0; marker < 8; marker++ {
		tests = append(tests, struct {
			name   string
			mutate func([]byte, []int)
		}{fmt.Sprintf("missing-distinct-marker-%d", marker), func(image []byte, offsets []int) {
			clear(image[offsets[marker] : offsets[marker]+96])
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image, offsets := watermarkDotnetTestImage(768)
			test.mutate(image, offsets)
			path := watermarkDotnetTestFile(t, image)
			input, err := inspect("dotnet", "app", path)
			if err != nil {
				t.Fatal("fixture must pass ordinary managed-PE inspection", err)
			}
			prepared, entries, err := prepareDotnetWatermark(input, strings.Repeat("b", 32))
			if err == nil || len(entries) != 0 || len(prepared.entryEdits) != 0 {
				t.Fatal("missing, unmapped or discarded distinct marker accepted", err)
			}
			for _, explanation := range []string{"missing C# watermark slots", "include AuthGo.Watermark.cs", "trim", "AOT", "single-file", "unsupported"} {
				if !strings.Contains(err.Error(), explanation) {
					t.Fatalf("missing actionable diagnostic %q: %v", explanation, err)
				}
			}
			watermarkDotnetTestPublicationRefusal(t, path, image, "missing C# watermark slots")
		})
	}
}

func watermarkDotnetTestPublicationRefusal(t *testing.T, path string, original []byte, reason string) {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "unpublished")
	err := CreateWatermarkedDotnet(path, destination, Payload{}, bytes.Repeat([]byte{7}, 32))
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("public packer did not propagate refusal %q: %v", reason, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("unsupported assembly published output", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatal("unsupported assembly changed input", err)
	}
}

func TestDotnetWatermarkRejectsNativeAOTAndReadyToRun(t *testing.T) {
	for _, test := range []struct {
		name           string
		mutate         func([]byte)
		prepareReason  string
		inspectRejects bool
		publishReason  string
	}{
		{"not-PE-unknown-machine", func(image []byte) { image[0] = 0xff; image[1] = 0xff }, "requires managed PE", true, "requires a managed PE"},
		// Clearing MZ can be accepted as a COFF object by debug/pe, but must
		// still be rejected for lacking a managed executable optional header.
		{"COFF-without-optional-header", func(image []byte) { clear(image[:2]) }, "invalid encrypted payload", true, "invalid encrypted payload"},
		// Native/AOT output without a CLR directory is rejected by inspection;
		// prepare is also checked directly, without pretending inspection passed.
		{"native-no-CLR-directory", func(image []byte) { clear(image[152+96+14*8 : 152+96+15*8]) }, "", true, "native or mixed-mode"},
		{"mixed-mode-no-IL-only", func(image []byte) { binary.LittleEndian.PutUint32(image[528:], 0) }, "native, mixed, AOT or ReadyToRun", true, "native or mixed-mode"},
		{"native-entrypoint", func(image []byte) { binary.LittleEndian.PutUint32(image[528:], 0x11) }, "native, mixed, AOT or ReadyToRun", true, "native or mixed-mode"},
		{"ReadyToRun-directory-RVA", func(image []byte) { binary.LittleEndian.PutUint32(image[512+64:], 0x2300) }, "native, mixed, AOT or ReadyToRun", false, "native, mixed, AOT or ReadyToRun"},
		{"ReadyToRun-directory-size", func(image []byte) { binary.LittleEndian.PutUint32(image[512+68:], 16) }, "native, mixed, AOT or ReadyToRun", false, "native, mixed, AOT or ReadyToRun"},
		{"ReadyToRun-directory-both", func(image []byte) {
			binary.LittleEndian.PutUint32(image[512+64:], 0x2300)
			binary.LittleEndian.PutUint32(image[512+68:], 16)
		}, "native, mixed, AOT or ReadyToRun", false, "native, mixed, AOT or ReadyToRun"},
	} {
		t.Run(test.name, func(t *testing.T) {
			image, _ := watermarkDotnetTestImage(768)
			test.mutate(image)
			path := watermarkDotnetTestFile(t, image)
			_, err := inspect("dotnet", "app", path)
			if (err != nil) != test.inspectRejects {
				t.Fatal("unexpected ordinary PE inspection result", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			input := source{file: File{Kind: "dotnet", Encoding: "tar"}, entries: []entry{{name: "App.dll", path: path, info: info}}}
			prepared, entries, err := prepareDotnetWatermark(input, strings.Repeat("c", 32))
			if err == nil || test.prepareReason != "" && !strings.Contains(err.Error(), test.prepareReason) || len(entries) != 0 || len(prepared.entryEdits) != 0 {
				t.Fatalf("native/AOT/ReadyToRun image accepted or wrong diagnostic: %v", err)
			}
			watermarkDotnetTestPublicationRefusal(t, path, image, test.publishReason)
		})
	}
}
