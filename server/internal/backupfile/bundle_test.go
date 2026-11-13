package backupfile

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleContainsActualKey(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	dst := filepath.Join(dir, "backup.zip")
	os.WriteFile(db, []byte("snapshot"), 0600)
	key := bytes.Repeat([]byte{8}, 32)
	if e := Write(db, dst, key); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	got := map[string]string{}
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		got[f.Name] = string(b)
	}
	if got["authgo.db"] != "snapshot" || got["master.key"] != base64.StdEncoding.EncodeToString(key)+"\n" {
		t.Fatal("incomplete bundle")
	}
	st, _ := os.Stat(dst)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
}
