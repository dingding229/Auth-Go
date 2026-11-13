package ipinfo

import (
	"authgo/internal/netpolicy"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxCompressedBytes int64 = 128 << 20
const downloadHost = "download.db-ip.com"

// Verified from https://download.db-ip.com/free/ and its linked Lite download pages.
func downloadURL(kind string, month time.Time) string {
	return fmt.Sprintf("https://%s/free/dbip-%s-lite-%s.mmdb.gz", downloadHost, kind, month.Format("2006-01"))
}
func redirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
		return errors.New("不允许跨主机或非 HTTPS 重定向")
	}
	return nil
}
func downloadClient() *http.Client {
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(host, downloadHost) || port != "443" {
			return nil, errors.New("IP 库下载主机无效")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("IP 库下载域名无地址")
		}
		// Pin the checked addresses for this connection to prevent DNS rebinding.
		for _, ip := range ips {
			if !netpolicy.PublicIP(ip) {
				return nil, errors.New("IP 库下载域名包含非公网地址")
			}
		}
		var last error
		for _, ip := range ips {
			conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}
	return &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: redirect}
}

// limitedCompressed rejects excess compressed bytes even if gzip ends before them.
type compressedReader struct {
	r io.Reader
	n int64
}

func (r *compressedReader) Read(b []byte) (int, error) {
	if r.n > MaxCompressedBytes {
		return 0, errCompressedTooLarge
	}
	if int64(len(b)) > MaxCompressedBytes+1-r.n {
		b = b[:MaxCompressedBytes+1-r.n]
	}
	n, e := r.r.Read(b)
	r.n += int64(n)
	if r.n > MaxCompressedBytes {
		return n, errCompressedTooLarge
	}
	return n, e
}
func (s *Service) fetch(ctx context.Context, client *http.Client, raw, kind string) (*prepared, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != downloadHost || u.User != nil {
		return nil, errors.New("只允许官方 HTTPS 下载地址")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, errNotPublished
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("IP 库下载失败")
	}
	if resp.ContentLength > MaxCompressedBytes {
		return nil, errCompressedTooLarge
	}
	limited := &compressedReader{r: resp.Body}
	gz, err := gzip.NewReader(limited)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errInvalidGzip
		}
		return nil, err
	}
	defer gz.Close()
	p, err := s.prepare(ctx, kind, "db-ip", gz)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errInvalidGzip
		}
		return nil, err
	}
	// Drain to validate trailing compressed bytes, gzip checksum and the wire limit.
	if _, err = io.Copy(io.Discard, limited); err != nil {
		p.discard()
		return nil, err
	}
	return p, nil
}
func (s *Service) downloadDB(ctx context.Context, kind string, month time.Time) (*prepared, error) {
	client := downloadClient()
	defer client.CloseIdleConnections()
	return s.fetch(ctx, client, downloadURL(kind, month), kind)
}
func (s *Service) Enable(ctx context.Context) error { return s.update(ctx, true) }
func (s *Service) Update(ctx context.Context) error { return s.update(ctx, false) }
func (s *Service) update(ctx context.Context, enable bool) error {
	s.op.Lock()
	defer s.op.Unlock()
	return s.updateLocked(ctx, enable)
}
func (s *Service) updateLocked(ctx context.Context, enable bool) error {
	s.syncing.Store(true)
	defer s.syncing.Store(false)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	state := s.snapshot()
	if !state.Enabled && !enable {
		return errDisabled
	}
	now := s.now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	changes := make(map[string]*prepared)
	success := false
	defer func() {
		if !success {
			for _, p := range changes {
				p.discard()
			}
		}
	}()
	current := true
	skippedUpload := false
	for _, kind := range []string{"city", "asn"} {
		db := state.City
		if kind == "asn" {
			db = state.ASN
		}
		if db != nil && db.Source == "upload" && !state.Schedule.Enabled {
			skippedUpload = true
			continue
		}
		p, err := s.download(ctx, kind, month)
		if errors.Is(err, errNotPublished) {
			current = false
			if db != nil {
				continue
			} // Never downgrade or damage a working library at month boundaries.
			p, err = s.download(ctx, kind, month.AddDate(0, -1, 0))
			if errors.Is(err, errNotPublished) {
				continue
			}
		}
		if err != nil {
			s.recordSyncError(err)
			return err
		}
		changes[kind] = p
	}
	// No files available is a pending publication, not a destructive failure or an enabled empty library.
	state.Enabled = state.Enabled || len(changes) > 0
	state.Schedule.LastSyncAt = &now
	state.Schedule.LastResult = "成功"
	if skippedUpload {
		state.Schedule.LastResult = "已同步其他库，保留上传库"
		if len(changes) == 0 {
			state.Schedule.LastResult = "保留上传库，未替换"
		}
	}
	state.Schedule.Failures = 0
	state.Schedule.NextRunAt = nil
	if !current {
		state.Schedule.LastResult = "等待 DB-IP 发布"
		state.Schedule.Failures = s.snapshot().Schedule.Failures + 1
	}
	if state.Schedule.Enabled {
		at := nextScheduled(now, state.Schedule.SyncPlan)
		if !current {
			at = retryAt(now, state.Schedule.Failures)
		}
		state.Schedule.NextRunAt = &at
	}
	if err := s.commit(ctx, state, changes); err != nil {
		s.recordSyncError(err)
		return err
	}
	success = true
	return nil
}
