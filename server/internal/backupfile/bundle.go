// Package backupfile bundles SQLite snapshots with their actual encryption key.
package backupfile

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Write(database, destination string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("备份主密钥无效")
	}
	src, e := os.Open(database)
	if e != nil {
		return e
	}
	defer src.Close()
	f, e := os.CreateTemp(filepath.Dir(destination), ".backup-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	z := zip.NewWriter(f)
	for _, name := range []string{"authgo.db", "master.key"} {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0600)
		w, e := z.CreateHeader(h)
		if e != nil {
			return e
		}
		if name == "authgo.db" {
			_, e = io.Copy(w, src)
		} else {
			_, e = io.WriteString(w, base64.StdEncoding.EncodeToString(key)+"\n")
		}
		if e != nil {
			return e
		}
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), destination)
}
