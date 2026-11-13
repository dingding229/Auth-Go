package automation

import (
	"authgo/internal/apperror"
	"authgo/internal/backupfile"
	cryptoutil "authgo/internal/crypto"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

var backupName = regexp.MustCompile(`^authgo-[0-9]{8}T[0-9]{6}Z-[a-zA-Z0-9_-]+\.db$`)

type BackupInfo struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	BundleReady bool      `json:"bundle_ready"`
}

func (s *Service) backupDir() string { return filepath.Join(s.dataDir, "backups") }
func (s *Service) ListBackups() ([]BackupInfo, error) {
	rows := []BackupInfo{}
	if s.dataDir == "" {
		return rows, nil
	}
	entries, e := os.ReadDir(s.backupDir())
	if errors.Is(e, os.ErrNotExist) {
		return rows, nil
	}
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if !backupName.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || !regularBackup(filepath.Join(s.backupDir(), entry.Name()+".zip")) {
			continue
		}
		rows = append(rows, BackupInfo{Name: entry.Name(), Size: info.Size(), CreatedAt: info.ModTime().UTC(), BundleReady: regularBackup(filepath.Join(s.backupDir(), entry.Name()+".zip"))})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].Name > rows[j].Name
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	return rows, nil
}
func regularBackup(path string) bool {
	st, e := os.Lstat(path)
	return e == nil && st.Mode().IsRegular()
}
func (s *Service) OpenBackup(name string) (*os.File, error) {
	if s.dataDir == "" {
		return nil, apperror.Invalid("未配置数据目录")
	}
	if !backupName.MatchString(name) || filepath.Base(name) != name {
		return nil, apperror.Invalid("备份文件名无效")
	}
	path := filepath.Join(s.backupDir(), name+".zip")
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, apperror.NotFound()
	}
	return os.Open(path)
}
func (s *Service) Backup(parent context.Context) (BackupInfo, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	var out BackupInfo
	if s.dataDir == "" {
		return out, apperror.Invalid("未配置数据目录")
	}
	if e := os.MkdirAll(s.backupDir(), 0700); e != nil {
		return out, e
	}
	random, e := cryptoutil.RandomString(12)
	if e != nil {
		return out, e
	}
	name := "authgo-" + s.now().UTC().Format("20060102T150405Z") + "-" + random + ".db"
	finalPath := filepath.Join(s.backupDir(), name)
	path := finalPath + ".partial"
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return out, e
	}
	if e := file.Close(); e != nil {
		os.Remove(path)
		return out, e
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
			_ = os.Remove(finalPath + ".zip")
		}
	}()
	// Independent read-only source connection: a snapshot must not monopolize
	// the application's single writer pool. VACUUM INTO reads the WAL consistently.
	source, e := filepath.Abs(filepath.Join(s.dataDir, "authgo.db"))
	if e != nil {
		return out, e
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(source), RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}).String()
	pool, e := sql.Open("sqlite", uri)
	if e != nil {
		return out, e
	}
	defer pool.Close()
	pool.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	if _, e := pool.ExecContext(ctx, "VACUUM INTO ?", path); e != nil {
		return out, e
	}
	synced, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		return out, e
	}
	e = synced.Sync()
	closeError := synced.Close()
	if e == nil {
		e = closeError
	}
	if e != nil {
		return out, e
	}
	info, e := os.Stat(path)
	if e != nil {
		return out, e
	}
	if e := backupfile.Write(path, finalPath+".zip", s.masterKey); e != nil {
		return out, e
	}
	if e := os.Rename(path, finalPath); e != nil {
		return out, e
	}
	out = BackupInfo{Name: name, Size: info.Size(), CreatedAt: info.ModTime().UTC(), BundleReady: true}
	complete = true
	rows, e := s.ListBackups()
	if e != nil {
		return out, e
	}

	others := make([]BackupInfo, 0, len(rows))
	for _, old := range rows {
		if old.Name != name {
			others = append(others, old)
		}
	}
	for _, old := range others[minimum(6, len(others)):] {
		if err := os.Remove(filepath.Join(s.backupDir(), old.Name+".zip")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
		if e := os.Remove(filepath.Join(s.backupDir(), old.Name)); e != nil {
			return out, e
		}
	}

	return out, nil
}
func minimum(a, b int) int {
	if a < b {
		return a
	}
	return b
}
