package pack

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNodeWatermarkDirectivePlacementAndStreaming(t *testing.T) {
	cases := []struct {
		name, source string
		at           int
	}{
		{"none", "module.exports=42;", 0},
		{"strict", "\"use strict\";module.exports=42;", 13},
		{"ASI", "\"use strict\"\nmodule.exports=42;", 12},
		{"prefixincrement", "\"use strict\"\n++counter;", 12},
		{"expression", "\"use strict\"\n+foo;", 0},
		{"keyword-in", "\"use strict\"\nin object;", 0},
		{"keyword-instanceof", "\"use strict\"\ninstanceof Object;", 0},
		{"BOM", "\ufeffmodule.exports=42;", 3},
		{"shebang", "#!/usr/bin/node\nmodule.exports=42;", 16},
		{"comment", "/*hello*/\"use strict\";\nmodule.exports=42;", 22},
		{"block-ASI", "\"use strict\"/*\n*/counter++;", 12},
	}
	tag := strings.Repeat("a", 32)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "core.cjs")
			if e := os.WriteFile(name, []byte(test.source), 0600); e != nil {
				t.Fatal(e)
			}
			input, e := inspect("node", "core", name)
			if e != nil {
				t.Fatal(e)
			}
			prepared, entries, e := prepareNodeWatermark(input, tag)
			if e != nil {
				t.Fatal(e)
			}
			if prepared.insertAt != int64(test.at) {
				t.Fatalf("placement %d want%d", prepared.insertAt, test.at)
			}
			r, e := prepared.reader()
			if e != nil {
				t.Fatal(e)
			}
			data, e := io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			if int64(len(data)) != prepared.file.Size || len(entries) != 1 || len(entries[0].Offsets) != 8 || entries[0].Path == nil {
				t.Fatal("bad Node private index")
			}
			if !strings.Contains(string(prepared.inserted), ";void [") || !bytes.HasSuffix(prepared.inserted, []byte("];")) {
				t.Fatal("Node slots must use an inert expression, not public object storage")
			}
			for _, s := range entries[0].Offsets {
				n, e := strconv.Atoi(s)
				if e != nil || !bytes.Equal(data[n:n+96], []byte(tag+strings.Repeat("0", 64))) {
					t.Fatal("node literal offset", e)
				}
			}
			original, e := os.ReadFile(name)
			if e != nil || string(original) != test.source {
				t.Fatal("source overwritten", e)
			}
			reconstructed := append([]byte(nil), data[:test.at]...)
			reconstructed = append(reconstructed, data[test.at+len(prepared.inserted):]...)
			if string(reconstructed) != test.source {
				t.Fatal("original code altered")
			}
		})
	}
}
func TestNodeWatermarkMalformedPreambleRejects(t *testing.T) {
	for _, text := range []string{"/* open", "\"use strict", "\"escape\\"} {
		file := filepath.Join(t.TempDir(), "bad.cjs")
		if e := os.WriteFile(file, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(file)
		if e != nil {
			t.Fatal(e)
		}
		_, e = nodeWatermarkInsertion(f, int64(len(text)))
		f.Close()
		if e == nil {
			t.Fatal("malformed directive accepted")
		}
	}
}
