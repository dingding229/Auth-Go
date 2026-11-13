package sdk

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strconv"
)

const ProtectedFooterSize = 64

var protectedMagic = [16]byte{'A', 'U', 'T', 'H', 'G', 'O', '-', 'S', 'T', 'U', 'B', '-', 'v', '1', 0, 0}

// ProtectedImage is a bounded view into the running executable, not a trusted
// payload until UnlockPayload and every ciphertext chunk have authenticated.
type ProtectedImage struct {
	Payload       Payload
	Source        io.ReaderAt
	Start, Length int64
	Index         int
}

func ReadProtectedImage(src io.ReaderAt, size int64) (ProtectedImage, error) {
	bad := ProtectedImage{}
	if size < ProtectedFooterSize {
		return bad, payloadInvalid
	}
	footer := make([]byte, ProtectedFooterSize)
	n, e := src.ReadAt(footer, size-ProtectedFooterSize)
	if n != len(footer) || (e != nil && e != io.EOF) {
		return bad, payloadInvalid
	}
	for i, b := range protectedMagic {
		if footer[i] != b {
			return bad, payloadInvalid
		}
	}
	if binary.BigEndian.Uint32(footer[16:20]) != 1 || binary.BigEndian.Uint32(footer[20:24]) != 0 {
		return bad, payloadInvalid
	}
	for _, b := range footer[48:] {
		if b != 0 {
			return bad, payloadInvalid
		}
	}
	lengths := []uint64{binary.BigEndian.Uint64(footer[24:32]), binary.BigEndian.Uint64(footer[32:40]), binary.BigEndian.Uint64(footer[40:48])}
	if lengths[0] < 64 || lengths[1] == 0 || lengths[1] > 65536 {
		return bad, payloadInvalid
	}
	sum := uint64(ProtectedFooterSize)
	for _, n := range lengths {
		if n > math.MaxInt64 || sum > math.MaxInt64-n {
			return bad, payloadInvalid
		}
		sum += n
	}
	if sum != uint64(size) {
		return bad, payloadInvalid
	}
	raw := make([]byte, int(lengths[1]))
	if n, e = src.ReadAt(raw, int64(lengths[0])); n != len(raw) || (e != nil && e != io.EOF) {
		return bad, payloadInvalid
	}
	p, e := ParsePayload(raw)
	if e != nil {
		return bad, e
	}
	files, e := p.Files()
	if e != nil {
		return bad, e
	}
	offset := int64(lengths[0] + lengths[1])
	total := int64(0)
	index := -1
	start, length := int64(0), int64(0)
	for i, f := range files {
		span := PayloadCipherSize(f.Size)
		if span < 16 || span > math.MaxInt64-total {
			return bad, payloadInvalid
		}
		if f.Kind == "protect" {
			if index != -1 {
				return bad, payloadInvalid
			}
			index = i
			start = offset + total
			length = span
		}
		total += span
	}
	if index < 0 || uint64(total) != lengths[2] {
		return bad, payloadInvalid
	}
	return ProtectedImage{p, src, start, length, index}, nil
}

// Decrypt requires K||WM material and
// dst must support random access (the loader supplies anonymous memfd/tmpfs).
// All metadata chunks authenticate first, followed by all selected code chunks;
// every selected slot is validated before the first watermark byte is written.
func (p ProtectedImage) Decrypt(dst io.Writer, material []byte) error {
	if p.Payload.V != 2 || !validPayloadMaterial(p.Payload, material) {
		return payloadInvalid
	}
	target, ok := dst.(payloadWatermarkTarget)
	if !ok {
		return payloadInvalid
	}
	files, e := p.Payload.Files()
	if e != nil || p.Index < 0 || p.Index >= len(files) || files[p.Index].Kind != "protect" || p.Length != PayloadCipherSize(files[p.Index].Size) {
		return payloadInvalid
	}
	// Recover the ciphertext-area base without altering the protected footer/layout.
	base := p.Start
	for _, f := range files[:p.Index] {
		span := PayloadCipherSize(f.Size)
		if span > base {
			return payloadInvalid
		}
		base -= span
	}
	metadata, start := -1, base
	metaStart := int64(0)
	for i, f := range files {
		span := PayloadCipherSize(f.Size)
		if start < 0 || start > math.MaxInt64-span {
			return payloadInvalid
		}
		if f.Kind == "watermark" {
			metadata, metaStart = i, start
		}
		start += span
	}
	if metadata < 0 {
		return payloadInvalid
	}
	var private bytes.Buffer
	private.Grow(int(files[metadata].Size)) // manifest validation caps this at 8 MiB
	defer func() { clear(private.Bytes()) }()
	metaLength := PayloadCipherSize(files[metadata].Size)
	if e = DecryptPayloadFile(&private, io.NewSectionReader(p.Source, metaStart, metaLength), metaLength, p.Payload, material[:32], metadata); e != nil {
		return e
	}
	if int64(private.Len()) != files[metadata].Size {
		return payloadInvalid
	}
	index, e := parsePayloadWatermarkIndex(private.Bytes(), files)
	if e != nil {
		return e
	}
	var selected *payloadWatermarkFile
	for i := range index.Files {
		if index.Files[i].Index == strconv.Itoa(p.Index) {
			selected = &index.Files[i]
			break
		}
	}
	if selected == nil || len(selected.Entries) != 1 || len(selected.Entries[0].Path) != 0 {
		return payloadInvalid
	}
	if e = DecryptPayloadFile(dst, io.NewSectionReader(p.Source, p.Start, p.Length), p.Length, p.Payload, material[:32], p.Index); e != nil {
		return e
	}
	return applyPayloadWatermark(target, files[p.Index].Size, index.Tag, selected.Entries[0], material[32:])
}
