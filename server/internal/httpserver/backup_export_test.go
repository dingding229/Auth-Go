package httpserver

import (
	"authgo/internal/backupfile"
	"authgo/internal/model"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBackupExportPasswordAndAudit(t *testing.T) {
	f, s := automationFixture(t)
	token := data(f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 200))["access_token"].(string)
	backup, err := s.Backup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, _ := s.BackupStatus(t.Context())
	if status.LastDownloadedAt != nil {
		t.Fatal("creating an automatic backup counted as download")
	}
	f.request(t, "POST", "/system/backups/"+backup.Name+"/export", token, gin.H{"password": "short"}, 400)
	f.request(t, "POST", "/system/backups/"+backup.Name+"/export", "", gin.H{"password": "a private backup password"}, 401)
	password := "a private backup password"
	body, _ := json.Marshal(gin.H{"password": password})
	req := httptest.NewRequest("POST", "/api/v1/admin/system/backups/"+backup.Name+"/export", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), ".zip.enc") || strings.Contains(w.Body.String(), password) {
		t.Fatal("unsafe or failed export", w.Code)
	}
	var plain bytes.Buffer
	if err := backupfile.Decrypt(&plain, bytes.NewReader(w.Body.Bytes()), password); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(plain.Bytes(), []byte("PK")) {
		t.Fatal("export did not encrypt ZIP")
	}
	status, err = s.BackupStatus(t.Context())
	if err != nil || status.LastDownloadedAt == nil {
		t.Fatal("complete export did not record download", status, err)
	}
	var audit model.AuditLog
	if err := f.db.Where("action=?", "system.backup.download").Order("id DESC").First(&audit).Error; err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(audit)
	if strings.Contains(string(encoded), password) || audit.Details["encrypted"] != true {
		t.Fatal("audit contains password or lacks encryption flag")
	}
}

func TestBackupPartialRangeDoesNotCountAsDownload(t *testing.T) {
	f, s := automationFixture(t)
	token := data(f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 200))["access_token"].(string)
	backup, err := s.Backup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := func(partial bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/admin/system/backups/"+backup.Name, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if partial {
			req.Header.Set("Range", "bytes=0-127")
		}
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, req)
		return w
	}
	if w := request(true); w.Code != 206 {
		t.Fatal("range behavior changed", w.Code)
	}
	status, _ := s.BackupStatus(t.Context())
	if status.LastDownloadedAt != nil {
		t.Fatal("partial range counted as download")
	}
	if w := request(false); w.Code != 200 {
		t.Fatal("legacy ZIP download failed", w.Code)
	}
	status, _ = s.BackupStatus(t.Context())
	if status.LastDownloadedAt == nil {
		t.Fatal("legacy full ZIP download not recorded")
	}
}
