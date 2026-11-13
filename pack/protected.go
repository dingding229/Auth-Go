package pack

import (
	"bytes"
	"debug/elf"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

//go:embed stubs/*
var embeddedLaunchers embed.FS
var stubForArch = embeddedLauncher

func embeddedLauncher(arch string) ([]byte, error) {
	if arch != "amd64" && arch != "arm64" {
		return nil, errors.New("unsupported launcher architecture")
	}
	data, e := embeddedLaunchers.ReadFile("stubs/authgo-stub-linux-" + arch)
	if e != nil {
		return nil, errors.New("launcher missing: build authgo-pack with make build-pack")
	}
	file, e := elf.NewFile(bytes.NewReader(data))
	if e != nil {
		return nil, errors.New("invalid embedded launcher")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || arch == "amd64" && file.Machine != elf.EM_X86_64 || arch == "arm64" && file.Machine != elf.EM_AARCH64 {
		return nil, errors.New("embedded launcher architecture mismatch")
	}
	return data, nil
}

const protectedFooterSize = 64

var protectedMagic = [16]byte{'A', 'U', 'T', 'H', 'G', 'O', '-', 'S', 'T', 'U', 'B', '-', 'v', '1', 0, 0}

type protectedReplacement struct{ original, temp string }

func prepareProtected(s source, p Payload, cipherDirectory string) (protectedReplacement, error) {
	empty := protectedReplacement{}
	stub, e := stubForArch(s.file.Architecture)
	if e != nil {
		return empty, e
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 65536 {
		return empty, errors.New("protected payload metadata exceeds gateway limit")
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".authgo-protected-")
	if e != nil {
		return empty, errors.New("protected program staging failed")
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if e = f.Chmod(s.info.Mode().Perm()); e != nil {
		return empty, errors.New("protected program permissions failed")
	}
	if _, e = f.Write(stub); e != nil {
		return empty, errors.New("launcher write failed")
	}
	if _, e = f.Write(raw); e != nil {
		return empty, errors.New("payload metadata write failed")
	}
	manifestRaw, _ := b64.DecodeString(p.Manifest)
	m, e := decodeManifestVersion(manifestRaw, p.V)
	if e != nil {
		return empty, e
	}
	var size uint64
	for i, file := range m.Files {
		part, e := openSafe(filepath.Join(cipherDirectory, cipherName(i)))
		if e != nil {
			return empty, errors.New("ciphertext unavailable")
		}
		st, e := part.Stat()
		if e != nil || st.Size() != CipherSize(file.Size) {
			part.Close()
			return empty, errors.New("ciphertext length invalid")
		}
		n, e := io.Copy(f, part)
		part.Close()
		if e != nil || n != st.Size() {
			return empty, errors.New("ciphertext write failed")
		}
		size += uint64(n)
	}
	footer := append([]byte{}, protectedMagic[:]...)
	footer = binary.BigEndian.AppendUint32(footer, 1)
	footer = binary.BigEndian.AppendUint32(footer, 0)
	for _, length := range []uint64{uint64(len(stub)), uint64(len(raw)), size} {
		footer = binary.BigEndian.AppendUint64(footer, length)
	}
	footer = append(footer, make([]byte, 16)...)
	if _, e = f.Write(footer); e != nil {
		return empty, errors.New("footer write failed")
	}
	if e = f.Sync(); e != nil {
		return empty, errors.New("protected program sync failed")
	}
	if e = f.Close(); e != nil {
		return empty, errors.New("protected program close failed")
	}
	ok = true
	return protectedReplacement{s.path, name}, nil
}
