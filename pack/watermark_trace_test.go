package pack

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWatermarkSharedScanVectors(t *testing.T) {
	data, e := os.ReadFile("../sdk/vectors/watermark.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		V    int `json:"v"`
		Scan []struct {
			Name     string      `json:"name"`
			Tags     []string    `json:"tags"`
			Bytes    string      `json:"bytes_b64"`
			Chunk    int         `json:"chunk_size"`
			Cancel   bool        `json:"cancel_before"`
			Expected TraceResult `json:"expected"`
		} `json:"scan"`
	}
	if e = json.Unmarshal(data, &vectors); e != nil {
		t.Fatal(e)
	}
	if vectors.V != 1 || len(vectors.Scan) < 20 {
		t.Fatal("missing shared cases")
	}
	for _, v := range vectors.Scan {
		t.Run(v.Name, func(t *testing.T) {
			raw, e := base64.StdEncoding.DecodeString(v.Bytes)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if v.Cancel {
				cancel()
			}
			got, e := scanWatermark(ctx, bytes.NewReader(raw), int64(len(raw)), v.Tags, v.Chunk)
			if e != nil {
				t.Fatal(e)
			}
			a, b := got, v.Expected
			a.Candidates = nil
			a.Warnings = nil
			b.Candidates = nil
			b.Warnings = nil
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("result %#v want %#v", a, b)
			}
		})
	}
}
func TestWatermarkTraceCLIAndInvalidParameters(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "export.class")
	tag := strings.Repeat("a", 32)
	value := strings.Repeat("b", 64)
	if e := os.WriteFile(file, []byte(tag+value), 0600); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	if code := Run([]string{"trace", "--tag", tag, file}, &out, &err); code != 0 {
		t.Fatal(code, err.String())
	}
	var got TraceResult
	if e := json.Unmarshal(out.Bytes(), &got); e != nil || got.Status != "found" || got.Watermark != value || got.Count != 1 {
		t.Fatal("CLI not scanning actual input", e)
	}
	for _, args := range [][]string{{"trace"}, {"trace", "--tag", "bad", file}, {"trace", "--tag", tag, dir}, {"trace", "--tag", tag, file, "extra"}} {
		out.Reset()
		err.Reset()
		if Run(args, &out, &err) == 0 {
			t.Fatal("invalid CLI accepted", args)
		}
	}
	for _, tags := range [][]string{nil, {"x"}, {strings.Repeat("A", 32)}} {
		if _, e := ScanWatermark(context.Background(), bytes.NewReader(nil), 0, tags); e == nil {
			t.Fatal("invalid tags accepted")
		}
	}
	if _, e := scanWatermark(context.Background(), bytes.NewReader(nil), -1, []string{tag}, 64); e == nil {
		t.Fatal("negative size")
	}
}

func TestTraceCandidateCapAndPartialCLI(t *testing.T) {
	tag := strings.Repeat("a", 32)
	var raw strings.Builder
	for i := 1; i <= traceMaxCandidates+1; i++ {
		fmt.Fprintf(&raw, "%s%064x!", tag, i)
	}
	data := []byte(raw.String())
	got, e := ScanWatermark(context.Background(), bytes.NewReader(data), int64(len(data)), []string{tag})
	if e != nil || got.Status != "partial" || got.Complete || got.Watermark != "" || got.Slots != traceMaxCandidates || len(got.Candidates) != traceMaxCandidates {
		t.Fatal("candidate cap not fail-incomplete", e)
	}
	file := filepath.Join(t.TempDir(), "truncated.zip")
	if e = os.WriteFile(file, []byte("PK\x03\x04"), 0600); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	if code := Run([]string{"trace", "--tag", tag, file}, &out, &err); code != 2 {
		t.Fatal("partial CLI must exit2", code, err.String())
	}
	var result TraceResult
	if e = json.Unmarshal(out.Bytes(), &result); e != nil || result.Status != "partial" || result.Complete {
		t.Fatal("partial JSON", e)
	}
}
