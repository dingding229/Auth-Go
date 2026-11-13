// Package ipinfo resolves IP metadata locally. Only explicit database updates use the network.
package ipinfo

import (
	"authgo/internal/netpolicy"
	"context"
	"encoding/json"
	"errors"
	"github.com/oschwald/maxminddb-golang"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const MaxDatabaseBytes int64 = 512 << 20
const cacheCapacity = 4096

// Info never contains the original IP (including in user-center responses).
type Info struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ASN         uint   `json:"asn"`
	ASOrg       string `json:"as_org"`
	Scope       string `json:"scope" enums:"public,private,loopback,unknown"`
}
type DatabaseStatus struct {
	Source       string    `json:"source"`
	DatabaseType string    `json:"database_type"`
	DataDate     time.Time `json:"data_date"`
	Size         int64     `json:"size"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type installed struct {
	DatabaseStatus
	File string `json:"file"`
}
type diskState struct {
	Enabled      bool       `json:"enabled"`
	City         *installed `json:"city,omitempty"`
	ASN          *installed `json:"asn,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	LastError    string     `json:"last_error"`
	CheckedMonth string     `json:"checked_month"`
	AttemptDate  string     `json:"attempt_date"`
}
type Status struct {
	Enabled        bool            `json:"enabled"`
	City           *DatabaseStatus `json:"city,omitempty"`
	ASN            *DatabaseStatus `json:"asn,omitempty"`
	UpdatedAt      *time.Time      `json:"updated_at,omitempty"`
	LastError      string          `json:"last_error"`
	Attribution    string          `json:"attribution,omitempty"`
	AttributionURL string          `json:"attribution_url,omitempty"`
}
type Service struct {
	op        sync.Mutex // serialize file transactions; never held by queries
	mu        sync.Mutex // protect readers, state and cache; close only after all queries complete
	dir       string
	state     diskState
	city, asn *maxminddb.Reader
	cache     map[string]Info
	download  func(context.Context, string, time.Time) (*prepared, error)
	now       func() time.Time
}

// New always returns a usable optional service. Broken state or databases disable
// enrichment in memory, without rewriting state or deleting any retained files.
func New(dataDir string) (*Service, error) {
	s := &Service{dir: filepath.Join(dataDir, "ipdb"), cache: make(map[string]Info), now: time.Now}
	s.download = s.downloadDB
	raw, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		s.degrade(errUnreadableState)
		return s, nil
	}
	if err = json.Unmarshal(raw, &s.state); err != nil {
		s.degrade(errInvalidState)
		return s, nil
	}
	s.state.LastError = safeStoredMessage(s.state.LastError)
	if !s.state.Enabled {
		return s, nil
	}
	for _, kind := range []string{"city", "asn"} {
		db := s.state.City
		if kind == "asn" {
			db = s.state.ASN
		}
		if db == nil {
			continue
		}
		if filepath.Base(db.File) != db.File || !strings.HasPrefix(db.File, "db-") {
			s.degrade(errInvalidState)
			return s, nil
		}
		// Startup deliberately checks metadata only. Full Verify and probe queries
		// are performed before accepting a download or upload, not on every boot.
		r, e := openDatabase(filepath.Join(s.dir, db.File), kind)
		if e != nil {
			s.degrade(e)
			return s, nil
		}
		if kind == "city" {
			s.city = r
		} else {
			s.asn = r
		}
	}
	if err = s.cleanUnused(); err != nil {
		s.degrade(err)
		return s, nil
	}
	return s, nil
}

// Called during construction or with mu held after a query detects corrupt data.
// No cleanup or writes are permitted on this path.
func (s *Service) degrade(err error) {
	if s.city != nil {
		_ = s.city.Close()
		s.city = nil
	}
	if s.asn != nil {
		_ = s.asn.Close()
		s.asn = nil
	}
	s.state = diskState{LastError: safeMessage(err)}
	s.cache = make(map[string]Info)
	slog.Warn("IP 库已降级停用，不影响授权服务", "reason", s.state.LastError)
}

// Recover unreferenced temporary generations after a crash without touching unrelated files.
func (s *Service) cleanUnused() error {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, f := range entries {
		name := f.Name()
		if !strings.HasPrefix(name, "db-") && !strings.HasPrefix(name, "state-") {
			continue
		}
		if s.state.City != nil && s.state.City.File == name || s.state.ASN != nil && s.state.ASN.File == name {
			continue
		}
		if e := os.Remove(filepath.Join(s.dir, name)); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Close() error {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.city != nil {
		err = errors.Join(err, s.city.Close())
		s.city = nil
	}
	if s.asn != nil {
		err = errors.Join(err, s.asn.Close())
		s.asn = nil
	}
	s.state.Enabled = false
	s.cache = make(map[string]Info)
	return err
}
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Status{Enabled: s.state.Enabled, UpdatedAt: s.state.UpdatedAt, LastError: s.state.LastError}
	if s.state.City != nil {
		v := s.state.City.DatabaseStatus
		out.City = &v
	}
	if s.state.ASN != nil {
		v := s.state.ASN.DatabaseStatus
		out.ASN = &v
	}
	for _, db := range []*installed{s.state.City, s.state.ASN} {
		if db != nil && db.Source == "db-ip" {
			out.Attribution = "IP 地理位置数据由 DB-IP.com 提供"
			out.AttributionURL = "https://db-ip.com"
		}
	}
	return out
}

type named struct {
	Names map[string]string `maxminddb:"names"`
	Code  string            `maxminddb:"iso_code"`
}
type record struct {
	Country           named   `maxminddb:"country"`
	RegisteredCountry named   `maxminddb:"registered_country"`
	Subdivisions      []named `maxminddb:"subdivisions"`
	City              named   `maxminddb:"city"`
	ASN               uint    `maxminddb:"autonomous_system_number"`
	ASOrg             string  `maxminddb:"autonomous_system_organization"`
	Traits            struct {
		ASN   uint   `maxminddb:"autonomous_system_number"`
		ASOrg string `maxminddb:"autonomous_system_organization"`
	} `maxminddb:"traits"`
}

func name(n named) string {
	if n.Names["zh-CN"] != "" {
		return n.Names["zh-CN"]
	}
	return n.Names["en"]
}

// LookupBatch deduplicates before looking up; a whole batch observes the same database generation.
// Nil services and disabled libraries produce no enrichment, preserving existing JSON.
func (s *Service) LookupBatch(ips []string) map[string]*Info {
	out := make(map[string]*Info)
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Enabled {
		return out
	}
	for _, raw := range ips {
		if _, ok := out[raw]; ok {
			continue
		}
		a, err := netip.ParseAddr(raw)
		info := Info{Scope: "unknown"}
		key := raw
		if err == nil {
			a = a.Unmap()
			key = a.String()
		}
		if cached, ok := s.cache[key]; ok {
			v := cached
			out[raw] = &v
			continue
		}
		switch {
		case err != nil:
		case a.IsLoopback():
			info.Scope = "loopback"
		case a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
			info.Scope = "private"
		case netpolicy.PublicIP(a):
			info.Scope = "public"
			ip := net.IP(a.AsSlice())
			if s.city != nil {
				var r record
				if err := s.city.Lookup(ip, &r); err != nil {
					s.degrade(errInvalidContent)
					return make(map[string]*Info)
				} else {
					country := r.Country
					if country.Code == "" {
						country = r.RegisteredCountry
					}
					info.CountryCode = country.Code
					info.Country = name(country)
					info.City = name(r.City)
					if len(r.Subdivisions) > 0 {
						info.Region = name(r.Subdivisions[0])
					}
				}
			}
			if s.asn != nil {
				var r record
				if err := s.asn.Lookup(ip, &r); err != nil {
					s.degrade(errInvalidContent)
					return make(map[string]*Info)
				} else {
					info.ASN = r.ASN
					info.ASOrg = r.ASOrg
					if info.ASN == 0 {
						info.ASN = r.Traits.ASN
						info.ASOrg = r.Traits.ASOrg
					}
				}
			}
		}
		if len(s.cache) >= cacheCapacity {
			s.cache = make(map[string]Info)
		}
		s.cache[key] = info
		v := info
		out[raw] = &v
	}
	return out
}
func (s *Service) Lookup(ip string) *Info { return s.LookupBatch([]string{ip})[ip] }

func openDatabase(path, kind string) (*maxminddb.Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		var pathError *os.PathError
		if errors.As(err, &pathError) {
			return nil, err
		}
		return nil, errInvalidMMDB
	}
	m := r.Metadata
	typ := strings.ToLower(m.DatabaseType)
	compatible := kind == "city" && (strings.Contains(typ, "city") || strings.Contains(typ, "location")) || kind == "asn" && (strings.Contains(typ, "asn") || strings.Contains(typ, "isp"))
	if !compatible {
		_ = r.Close()
		return nil, errTypeMismatch
	}
	if m.BinaryFormatMajorVersion != 2 || (m.IPVersion != 4 && m.IPVersion != 6) || m.NodeCount == 0 || m.BuildEpoch == 0 || m.BuildEpoch > uint(time.Now().Add(48*time.Hour).Unix()) {
		_ = r.Close()
		return nil, errInvalidMetadata
	}
	return r, nil
}
func validate(path, kind string) (*maxminddb.Reader, error) {
	r, err := openDatabase(path, kind)
	if err != nil {
		return nil, err
	}
	fail := func() (*maxminddb.Reader, error) { _ = r.Close(); return nil, errInvalidContent }
	if r.Verify() != nil {
		return fail()
	}
	// Decode an actual record as well as a normal lookup before accepting a file.
	networks := r.Networks(maxminddb.SkipAliasedNetworks)
	found := false
	for networks.Next() {
		var sample record
		if _, err = networks.Network(&sample); err != nil {
			return fail()
		}
		if kind == "city" && (sample.Country.Code != "" || sample.RegisteredCountry.Code != "" || name(sample.City) != "") || kind == "asn" && (sample.ASN != 0 || sample.Traits.ASN != 0) {
			found = true
			break
		}
	}
	if !found || networks.Err() != nil {
		return fail()
	}
	var sample record
	if err = r.Lookup(net.ParseIP("8.8.8.8"), &sample); err != nil {
		return fail()
	}
	return r, nil
}

type prepared struct {
	db     *installed
	reader *maxminddb.Reader
	path   string
}

func (p *prepared) discard() {
	if p == nil {
		return
	}
	_ = p.reader.Close()
	_ = os.Remove(p.path)
}
func (s *Service) prepare(ctx context.Context, kind, source string, in io.Reader) (*prepared, error) {
	if kind != "city" && kind != "asn" {
		return nil, errInvalidKind
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.dir, "db-*.mmdb")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(&contextReader{ctx, in}, MaxDatabaseBytes+1))
	if err != nil {
		return nil, err
	}
	if n > MaxDatabaseBytes {
		return nil, errDatabaseTooLarge
	}
	if err = f.Sync(); err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	r, err := validate(path, kind)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = r.Close()
		return nil, err
	}
	keep = true
	return &prepared{db: &installed{DatabaseStatus: DatabaseStatus{Source: source, DatabaseType: r.Metadata.DatabaseType, DataDate: time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC(), Size: n, UpdatedAt: s.now().UTC()}, File: filepath.Base(path)}, reader: r, path: path}, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func (s *Service) snapshot() diskState { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *Service) save(state diskState) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, "state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = json.NewEncoder(f).Encode(state); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.dir, "state.json"))
}
func (s *Service) commit(ctx context.Context, state diskState, changes map[string]*prepared) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Serialize the small manifest commit with lookups, including lazy damage
	// detection, so a stale pre-download snapshot cannot re-enable corrupt readers.
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state
	state.City = old.City
	state.ASN = old.ASN
	state.Enabled = old.Enabled || len(changes) > 0
	for kind, p := range changes {
		if kind == "city" {
			state.City = p.db
		} else {
			state.ASN = p.db
		}
	}
	now := s.now().UTC()
	state.UpdatedAt = &now
	state.LastError = ""
	// The manifest rename is the durable commit point for the entire pair.
	if err := s.save(state); err != nil {
		return err
	}
	for kind, p := range changes {
		if kind == "city" {
			if s.city != nil {
				_ = s.city.Close()
			}
			s.city = p.reader
		} else {
			if s.asn != nil {
				_ = s.asn.Close()
			}
			s.asn = p.reader
		}
	}
	s.state = state
	s.cache = make(map[string]Info)
	for _, db := range []*installed{old.City, old.ASN} {
		if db != nil && (state.City == nil || state.City.File != db.File) && (state.ASN == nil || state.ASN.File != db.File) {
			_ = os.Remove(filepath.Join(s.dir, db.File))
		}
	}
	return nil
}
func (s *Service) Upload(ctx context.Context, kind string, in io.Reader) error {
	s.op.Lock()
	defer s.op.Unlock()
	return s.upload(ctx, kind, in)
}

// upload requires op; multipart staging and commit are one serialized operation.
func (s *Service) upload(ctx context.Context, kind string, in io.Reader) error {
	p, err := s.prepare(ctx, kind, "upload", in)
	if err != nil {
		s.recordError(err)
		return err
	}
	state := s.snapshot()
	state.Enabled = true
	if err = s.commit(ctx, state, map[string]*prepared{kind: p}); err != nil {
		p.discard()
		s.recordError(err)
	}
	return err
}
func (s *Service) Delete(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state := diskState{}
	if err := s.save(state); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.city != nil {
		_ = s.city.Close()
		s.city = nil
	}
	if s.asn != nil {
		_ = s.asn.Close()
		s.asn = nil
	}
	s.state = state
	s.cache = make(map[string]Info)
	// Remove only generated database/state temporary files; never follow user-supplied paths.
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, f := range entries {
		if strings.HasPrefix(f.Name(), "db-") || strings.HasPrefix(f.Name(), "state-") {
			if e := os.Remove(filepath.Join(s.dir, f.Name())); e != nil {
				err = errors.Join(err, e)
			}
		}
	}
	return err
}
func (s *Service) recordError(err error) {
	// Do not persist URLs, upstream response bodies or request details.
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.AttemptDate = s.now().UTC().Format("2006-01-02")
	state.LastError = safeMessage(err)
	_ = s.save(state)
	s.state = state
}

// UsesDBIP exposes only attribution eligibility, never database paths or errors.
func (s *Service) UsesDBIP() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Enabled && (s.state.City != nil && s.state.City.Source == "db-ip" || s.state.ASN != nil && s.state.ASN.Source == "db-ip")
}
