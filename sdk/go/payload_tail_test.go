package sdk

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func protectedExpected(plain []byte) []byte {
	return append(append([]byte{}, plain...), bytes.Repeat([]byte(payloadV2Tag+strings.Repeat("2a", 32)), 8)...)
}
func protectedFixture(t *testing.T, plain []byte) ([]byte, []byte) {
	t.Helper()
	offsets := make([]string, 8)
	for i := range offsets {
		offsets[i] = strconv.Itoa(len(plain) + i*payloadSlotSize)
	}
	return payloadV2ProtectedFixture(t, append(append([]byte{}, plain...), payloadV2PlainSlots()...), payloadV2Index(t, offsets), false)
}
func TestProtectedTailBoundsAndDecrypt(t *testing.T) {
	plain := []byte("authenticated executable bytes")
	raw, key := protectedFixture(t, plain)
	image, e := ReadProtectedImage(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	var output payloadV2Memory
	if e = image.Decrypt(&output, key); e != nil || !bytes.Equal(output.bytes, protectedExpected(plain)) {
		t.Fatal("tail interop", e)
	}
	for _, name := range []string{"magic", "version", "flags", "stub-length", "metadata-length", "cipher-length", "reserved", "truncate"} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte{}, raw...)
			offset := len(b) - ProtectedFooterSize
			switch name {
			case "magic":
				b[offset] ^= 1
			case "version":
				b[offset+19] = 2
			case "flags":
				b[offset+23] = 1
			case "stub-length":
				binary.BigEndian.PutUint64(b[offset+24:], ^uint64(0))
			case "metadata-length":
				binary.BigEndian.PutUint64(b[offset+32:], 65537)
			case "cipher-length":
				binary.BigEndian.PutUint64(b[offset+40:], 1)
			case "reserved":
				b[offset+63] = 1
			case "truncate":
				b = b[:len(b)-1]
			}
			if _, e := ReadProtectedImage(bytes.NewReader(b), int64(len(b))); e == nil {
				t.Fatal("bad footer accepted")
			}
		})
	}
	tampered := append([]byte{}, raw...)
	tampered[image.Start] ^= 1
	image, e = ReadProtectedImage(bytes.NewReader(tampered), int64(len(tampered)))
	if e != nil {
		t.Fatal(e)
	}
	if e = image.Decrypt(&payloadV2Memory{}, key); e == nil {
		t.Fatal("tampered executable accepted")
	}
}
