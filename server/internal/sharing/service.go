// Package sharing detects distribution anomalies offline; it never participates in client verification.
package sharing

import (
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const batchSize = 512
const runTimeout = 2 * time.Minute

type Country struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}
type ASN struct {
	ASN   uint   `json:"asn"`
	Org   string `json:"org"`
	Count int64  `json:"count"`
}
type Summary struct {
	LicenseID     uint64     `json:"license_id" gorm:"primaryKey;autoIncrement:false"`
	Countries     []Country  `json:"countries" gorm:"serializer:json"`
	ASNs          []ASN      `json:"asns" gorm:"column:asns;serializer:json"`
	InstanceCount int64      `json:"instance_count"`
	FlaggedAt     *time.Time `json:"flagged_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	IgnoredUntil  *time.Time `json:"ignored_until"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (Summary) TableName() string { return "license_sharing" }

// LocalDB is implemented by ipinfo.Service. No remote lookup provider is supported.
type LocalDB interface {
	Status() ipinfo.Status
	LookupBatch([]string) map[string]*ipinfo.Info
}
type Service struct {
	db  *gorm.DB
	ips LocalDB
	now func() time.Time
	mu  sync.Mutex
}

func New(db *gorm.DB, ips LocalDB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, ips: ips, now: now}
}
func (s *Service) Available() bool {
	if s == nil || s.ips == nil {
		return false
	}
	if db, ok := s.ips.(*ipinfo.Service); ok && db == nil {
		return false
	}
	v := s.ips.Status()
	return v.Enabled && (v.City != nil || v.ASN != nil)
}

// ActiveSQL also requires a post-expiry scan before an ignored warning can return.
func ActiveSQL(alias string) string {
	return alias + ".flagged_at IS NOT NULL AND (" + alias + ".ignored_until IS NULL OR (" + alias + ".ignored_until<=? AND " + alias + ".updated_at>=" + alias + ".ignored_until))"
}
func (s *Service) Filter(q *gorm.DB, now time.Time) *gorm.DB {
	if !s.Available() {
		return q.Where("1=0")
	}
	ids := s.db.WithContext(q.Statement.Context).Model(&Summary{}).Select("license_id").Where(ActiveSQL("license_sharing"), now)
	return q.Where("licenses.id IN (?)", ids)
}
func (s *Service) WithFlag(q *gorm.DB, now time.Time) *gorm.DB {
	return q.Joins("LEFT JOIN license_sharing AS sharing ON sharing.license_id=licenses.id").Select("licenses.*, CASE WHEN "+ActiveSQL("sharing")+" THEN 1 ELSE 0 END AS sharing_flag", now)
}
func (s *Service) Count(ctx context.Context) (int64, error) {
	if !s.Available() {
		return 0, nil
	}
	var n int64
	e := s.db.WithContext(ctx).Model(&Summary{}).Where(ActiveSQL("license_sharing"), s.now().UTC()).Count(&n).Error
	return n, e
}

type sample struct {
	LicenseID    uint64
	IP           string
	LastSeenUnix int64
}

func eligible(q *gorm.DB, start, end time.Time) *gorm.DB {
	return q.Where("license_id IS NOT NULL AND success=1 AND action IN ('activate','verify','heartbeat') AND created_at>=? AND created_at<=?", start, end)
}

// The timestamp index would sort/materialize the whole window before LIMIT.
// Pin the migration's partial cursor index so each page can stream in key order.
func groupedPage(q *gorm.DB, start, end time.Time, license uint64, afterIP string) *gorm.DB {
	q = eligible(q.Model(&model.VerifyLog{}).Table("verify_logs INDEXED BY idx_verify_logs_sharing"), start, end)
	if license != 0 {
		q = q.Where("(license_id,ip)>(?,?)", license, afterIP)
	}
	return q.Select("license_id,ip,MAX(unixepoch(created_at)) AS last_seen_unix").Group("license_id,ip").Order("license_id,ip").Limit(batchSize)
}

type distribution struct {
	row       Summary
	countries map[string]int64
	asns      map[uint]ASN
	seen      map[string]bool
}

func newDistribution(id uint64, now time.Time) *distribution {
	return &distribution{row: Summary{LicenseID: id, UpdatedAt: now, Countries: []Country{}, ASNs: []ASN{}}, countries: map[string]int64{}, asns: map[uint]ASN{}, seen: map[string]bool{}}
}
func (d *distribution) add(v sample, info *ipinfo.Info) {
	if info == nil || info.Scope != "public" {
		return
	}
	address, e := netip.ParseAddr(v.IP)
	if e != nil {
		return
	}
	key := address.Unmap().String()
	// The input SQL already groups exact addresses; normalize alternate textual forms too.
	at := time.Unix(v.LastSeenUnix, 0).UTC()
	if d.row.LastSeenAt == nil || at.After(*d.row.LastSeenAt) {
		d.row.LastSeenAt = &at
	}
	if d.seen[key] {
		return
	}
	d.seen[key] = true
	d.row.InstanceCount++
	if info.CountryCode != "" {
		d.countries[info.CountryCode]++
	}
	if info.ASN != 0 {
		a := d.asns[info.ASN]
		a.ASN = info.ASN
		if info.ASOrg != "" {
			a.Org = info.ASOrg
		}
		a.Count++
		d.asns[info.ASN] = a
	}
}
func (d *distribution) finish(now time.Time) Summary {
	for code, count := range d.countries {
		d.row.Countries = append(d.row.Countries, Country{code, count})
	}
	for _, a := range d.asns {
		d.row.ASNs = append(d.row.ASNs, a)
	}
	sort.Slice(d.row.Countries, func(i, j int) bool { return d.row.Countries[i].Code < d.row.Countries[j].Code })
	sort.Slice(d.row.ASNs, func(i, j int) bool { return d.row.ASNs[i].ASN < d.row.ASNs[j].ASN })
	if len(d.row.Countries) > 3 || len(d.row.ASNs) > 5 {
		d.row.FlaggedAt = &now
	}
	return d.row
}
func (s *Service) save(ctx context.Context, row Summary) error {
	// INSERT SELECT avoids resurrecting a license deleted during the bounded scan.
	q := s.db.WithContext(ctx)
	countries, e := rowJSON(row.Countries)
	if e != nil {
		return e
	}
	asns, e := rowJSON(row.ASNs)
	if e != nil {
		return e
	}
	return q.Exec(`INSERT INTO license_sharing(license_id,countries,asns,instance_count,flagged_at,last_seen_at,updated_at)
 SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM licenses WHERE id=?)
 ON CONFLICT(license_id) DO UPDATE SET countries=excluded.countries,asns=excluded.asns,instance_count=excluded.instance_count,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at,flagged_at=CASE WHEN excluded.flagged_at IS NULL THEN NULL ELSE COALESCE(license_sharing.flagged_at,excluded.flagged_at) END`, row.LicenseID, countries, asns, row.InstanceCount, row.FlaggedAt, row.LastSeenAt, row.UpdatedAt, row.LicenseID).Error
}

var errUnavailable = errors.New("共享检测需要启用本地 IP 库")

// Tick uses grouped, keyset-paged reads, holds only one license's distinct addresses,
// and writes independently. Cancellation never clears untouched licenses.
func (s *Service) Tick(parent context.Context) error {
	if !s.Available() {
		return nil
	}
	if !s.mu.TryLock() {
		return nil
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()
	now := s.now().UTC()
	start := now.Add(-24 * time.Hour)
	var license uint64
	afterIP := ""
	var current *distribution
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		if !s.Available() {
			return errUnavailable
		}
		rows := []sample{}
		if e := groupedPage(s.db.WithContext(ctx), start, now, license, afterIP).Scan(&rows).Error; e != nil {
			return e
		}
		ips := make([]string, 0, len(rows))
		for _, v := range rows {
			ips = append(ips, v.IP)
		}
		locations := s.ips.LookupBatch(ips)
		if !s.Available() {
			return errUnavailable
		}
		for _, v := range rows {
			if e := ctx.Err(); e != nil {
				return e
			}
			if current != nil && current.row.LicenseID != v.LicenseID {
				if e := s.save(ctx, current.finish(now)); e != nil {
					return e
				}
				current = nil
			}
			if current == nil {
				current = newDistribution(v.LicenseID, now)
			}
			current.add(v, locations[v.IP])
			license, afterIP = v.LicenseID, v.IP
		}
		if len(rows) < batchSize {
			break
		}
	}
	if current != nil {
		if e := s.save(ctx, current.finish(now)); e != nil {
			return e
		}
	}
	if !s.Available() {
		return errUnavailable
	}
	// Keep ignored_until when logs disappear or retention removes the old window.
	ids := eligible(s.db.WithContext(ctx).Model(&model.VerifyLog{}), start, now).Select("license_id")
	return s.db.WithContext(ctx).Exec("UPDATE license_sharing SET countries='[]',asns='[]',instance_count=0,flagged_at=NULL,last_seen_at=NULL,updated_at=? WHERE license_id NOT IN (?)", now, ids).Error
}
