package licensing

import (
	"authgo/internal/model"
	"context"
	"fmt"
	"gorm.io/gorm/logger"
	"net/url"
	"strings"
	"testing"
	"time"
)

type readQueryLog struct {
	logger.Interface
	statements []string
}

func (l *readQueryLog) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	l.statements = append(l.statements, sql)
}

func TestLicenseReadModelNamesAndGroupedActivationCounts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	first := f.create(t)
	second := f.create(t)
	for i, status := range []string{"active", "active", "active", "unbound", "revoked"} {
		a := model.Activation{LicenseID: first.ID, Kind: "key", Value: fmt.Sprint(i), Token: fmt.Sprintf("readmodel-%d", i), Status: status}
		if e := f.db.Create(&a).Error; e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 24; i++ {
		f.create(t)
	}
	log := &readQueryLog{Interface: logger.Default}
	original := f.db.Logger
	f.db.Logger = log
	defer func() { f.db.Logger = original }()
	items, total, err := f.s.List(ctx, Filter{Query: listQuery(t, url.Values{"page_size": {"100"}})})
	if err != nil || total != 26 {
		t.Fatal(total, err)
	}
	if len(log.statements) > 6 {
		t.Fatalf("queries grew with rows (%d): %v", len(log.statements), log.statements)
	}
	grouped := 0
	for _, sql := range log.statements {
		if strings.Contains(strings.ToUpper(sql), "GROUP BY") {
			grouped++
		}
	}
	if grouped != 1 {
		t.Fatal("expected one grouped activation count", log.statements)
	}
	for _, item := range items {
		if item.AppName != f.app.Name {
			t.Fatal("software name missing", item)
		}
		want := int64(0)
		if item.ID == first.ID {
			want = 3
		}
		if item.ActiveActivations != want {
			t.Fatal(item.ID, item.ActiveActivations, want)
		}
	}
	detail, err := f.s.Get(ctx, first.ID)
	if err != nil || detail.AppName != f.app.Name || detail.ActiveActivations != 3 || detail.ActivationsTotal != 5 {
		t.Fatal(detail, err)
	}
	empty, err := f.s.Get(ctx, second.ID)
	if err != nil || empty.ActiveActivations != 0 {
		t.Fatal(empty, err)
	}
	activations, _, err := f.s.ListActivations(ctx, listQuery(t, url.Values{}), &first.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range activations {
		if a.LicenseKey != first.Key {
			t.Fatal("license key missing", a)
		}
	}
}
