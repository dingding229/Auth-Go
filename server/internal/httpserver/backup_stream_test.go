package httpserver

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupRealHTTPDeadlineAndRange(t *testing.T) {
	f, service := automationFixture(t)
	token := data(f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 200))["access_token"].(string)
	backup, err := service.Backup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	file, err := service.OpenBackup(backup.Name)
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	file.Close()
	// Sparse file is test data; the production route still streams a real os.File.
	if err = os.Truncate(path, 32<<20); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f.r)
	srv.Config.WriteTimeout = 10 * time.Millisecond
	srv.Start()
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/system/backups/"+backup.Name, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond) // force TCP backpressure beyond the ordinary budget
	n, err := io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if err != nil || n != 32<<20 || res.StatusCode != 200 {
		t.Fatal(n, err, res.StatusCode)
	}
	req.Header.Set("Range", "bytes=0-1023")
	res, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || len(raw) != 1024 || res.StatusCode != 206 {
		t.Fatal(err, len(raw), res.StatusCode)
	}
	// Verify no temporary copy of the streamed file was made.
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), backup.Name+".partial")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

type delayedBackup struct {
	*bytes.Reader
	delay time.Duration
}

func (r *delayedBackup) Read(b []byte) (int, error) { time.Sleep(r.delay); return r.Reader.Read(b) }
func TestBackupStreamAbsoluteBudgetStopsSlowTransfer(t *testing.T) {
	r := gin.New()
	r.GET("/stream", func(c *gin.Context) {
		serveBackup(c, &delayedBackup{bytes.NewReader(make([]byte, 8192)), 30 * time.Millisecond}, "backup.db", time.Now(), 5*time.Millisecond)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := srv.Client().Get(srv.URL + "/stream")
	if err == nil {
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err == nil {
			t.Fatal("stream exceeded its absolute deadline")
		}
	}
}
