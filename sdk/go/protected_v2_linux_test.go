//go:build linux

package sdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestProtectedV2MemfdWatermarkAndSeals(t *testing.T) {
	raw, material := payloadV2ProtectedFixture(t, payloadV2PlainSlots(), payloadV2Index(t, nil), false)
	image, e := ReadProtectedImage(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	fd, e := prepareProtected(image, material)
	clear(material[:32])
	if e != nil {
		clear(material)
		t.Fatal(e)
	}
	defer fd.Close()
	want := bytes.Repeat([]byte(payloadV2Tag+hex.EncodeToString(material[32:])), 8)
	clear(material)
	got, e := io.ReadAll(fd)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("unwatermarked executable", e)
	}
	link, e := os.Readlink("/proc/self/fd/" + fmtFD(fd))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(link, "memfd:") {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd.Fd(), 1034, 0)
		if errno != 0 || flags&15 != 15 {
			t.Fatal("unsealed v2 memfd")
		}
	} else {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(fd.Fd()), &fs) != nil || uint64(fs.Type) != tmpfsMagic || !strings.Contains(link, "(deleted)") {
			t.Fatal("persistent/named v2 executable")
		}
	}
}
func TestProtectedV2FreshMalformedWatermarkBlocksProofFallback(t *testing.T) {
	s, c, p, want := payloadV2TLSFixture(t)
	c.stubMode = true
	if _, e := c.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	if _, e := c.unlockPayloadMaterial(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if got, e := c.protectedCachedKey(p); e != nil || !bytes.Equal(got, want) {
		t.Fatal("missing control proof", e)
	}
	valid := s.payloadResponse
	s.mu.Lock()
	s.payloadResponse = func(raw json.RawMessage, data map[string]any) string {
		code := valid(raw, data)
		delete(data, "watermark")
		return code
	}
	s.mu.Unlock()
	got, e := c.unlockPayloadMaterial(context.Background(), p)
	var terminal *payloadWatermarkError
	if got != nil || !errors.As(e, &terminal) || protectedFallbackAllowed(e) {
		t.Fatal("launcher would reuse cached WM", e)
	}
	if !protectedFallbackAllowed(failure(NetworkError, "", nil)) {
		t.Fatal("network fallback policy changed")
	}
	if c.state.Refused {
		t.Fatal("malformed watermark treated as explicit refusal")
	}
}
