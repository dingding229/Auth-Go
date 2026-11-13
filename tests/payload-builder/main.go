// Test-only format builder/extractor. Never a replacement for the production
// CLI: fixed PUBLIC fixture keys and plaintext extraction are intentional here.
package main

import (
	"archive/tar"
	"authgo/pack"
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "", "test-only language")
	input := flag.String("input", "", "")
	out := flag.String("out", "", "")
	extract := flag.String("extract", "", "")
	config := flag.String("config", "", "")
	public := flag.String("public-key", "", "")
	keyID := flag.String("key-id", "key-test", "")
	app := flag.String("app-key", "app_test", "")
	version := flag.String("version", "1.0.0", "")
	flag.Parse()
	private, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x23}, 32))
	if e != nil {
		return e
	}
	pub := private.PublicKey().Bytes()
	if *public != "" {
		pub, e = base64.RawURLEncoding.Strict().DecodeString(*public)
		if e != nil {
			return e
		}
	}
	if *config == "" {
		raw, _ := json.Marshal(map[string]any{"url": "https://auth.example.test", "app_key": *app, "app_secret": "PUBLIC-FIXTURE-ONLY", "public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "gateway_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
		*config = "authgo2." + base64.RawURLEncoding.EncodeToString(raw)
	}
	p := pack.Payload{AppKey: *app, Version: *version, BuiltAt: "2026-11-09T00:00:00Z", KeyID: *keyID, Config: *config}
	switch *mode {
	case "native":
		e = pack.ProtectWatermarked(*input, *out, p, pub)
	case "node":
		e = pack.CreateWatermarkedNode(*input, *out, p, pub)
	case "python":
		e = pack.CreateWatermarkedPython(*input, *out, p, pub)
	case "java":
		e = pack.CreateWatermarkedJava(*input, *out, p, pub)
	case "dotnet":
		e = pack.CreateWatermarkedDotnet(*input, *out, p, pub)
	case "php":
		e = pack.CreateWatermarkedPHP(*input, *out, p, pub)
	default:
		return fmt.Errorf("unsupported test language")
	}
	if e != nil {
		return e
	}
	if *extract == "" {
		return nil
	}
	if *public != "" {
		return fmt.Errorf("fixed-fixture extraction cannot open another public key")
	}
	raw, e := os.ReadFile(filepath.Join(*out, "payload.json"))
	if e != nil {
		return e
	}
	p, e = pack.ParsePayload(raw)
	if e != nil {
		return e
	}
	key, e := pack.Unlock(p, private.Bytes())
	if e != nil {
		return e
	}
	defer clear(key)
	var m pack.Manifest
	raw, e = base64.RawURLEncoding.DecodeString(p.Manifest)
	if e != nil {
		return e
	}
	if e = json.Unmarshal(raw, &m); e != nil {
		return e
	}
	if e = os.MkdirAll(*extract, 0700); e != nil {
		return e
	}
	for i, file := range m.Files {
		f, e := os.Open(filepath.Join(*out, file.Path))
		if e != nil {
			return e
		}
		stat, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		var plain bytes.Buffer
		for j := uint64(0); j < uint64((file.Size+pack.ChunkSize-1)/pack.ChunkSize) || j == 0; j++ {
			block, e := pack.ReadChunk(f, stat.Size(), p, key, uint32(i), j)
			if e != nil {
				f.Close()
				return e
			}
			plain.Write(block)
			clear(block)
		}
		f.Close()
		if file.Kind == "watermark" {
			if e = os.WriteFile(filepath.Join(*extract, "index.json"), plain.Bytes(), 0600); e != nil {
				return e
			}
			continue
		}
		if file.Encoding == "raw" {
			if e = os.WriteFile(filepath.Join(*extract, "core.cjs"), plain.Bytes(), 0600); e != nil {
				return e
			}
			continue
		}
		reader := tar.NewReader(bytes.NewReader(plain.Bytes()))
		for {
			header, e := reader.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
			if filepath.IsAbs(header.Name) || strings.Contains(header.Name, "..") || strings.ContainsAny(header.Name, "\\:\x00") {
				return fmt.Errorf("unsafe test archive")
			}
			path := filepath.Join(*extract, header.Name)
			if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
				return e
			}
			data, e := io.ReadAll(reader)
			if e != nil {
				return e
			}
			if e = os.WriteFile(path, data, 0600); e != nil {
				return e
			}
			clear(data)
		}
	}
	fmt.Println("TEST_ONLY_FORMAT_EXTRACT_DONE")
	return nil
}
