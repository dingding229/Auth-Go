package service

import (
	"authgo/internal/db"
	"authgo/internal/model"
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestReleaseOwnFloatingKeepsProofAndDoesNotConsumeQuota(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	app := model.Application{Name: "a", AppKey: "a", AppSecretEncrypted: "s", PrivateKeyEncrypted: "p", PublicKey: "k"}
	d.Create(&app)
	u := model.EndUser{Name: "owner", Status: "active"}
	d.Create(&u)
	other := model.EndUser{Name: "other", Status: "active"}
	d.Create(&other)
	l := model.License{AppID: app.ID, UserID: &u.ID, Key: "K", Status: "active", VerifyMethods: []string{"KEY", "FLOATING"}, MaxActivations: 1, MatchMode: "all"}
	d.Create(&l)
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	until := now.Add(time.Hour)
	a := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "instance", Status: "active", Token: "generation", LeaseExpiresAt: &until}
	if e = d.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	s, _ := New(d, nil, nil, Options{Now: func() time.Time { return now }})
	if e = s.ReleaseSelf(context.Background(), l.ID, a.ID, other.ID); e == nil {
		t.Fatal("another user released instance")
	}
	if e = s.ReleaseSelf(context.Background(), l.ID, a.ID, u.ID); e != nil {
		t.Fatal(e)
	}

	if e := d.First(&model.Activation{}, a.ID).Error; !errors.Is(e, gorm.ErrRecordNotFound) {
		t.Fatal("released instance retained", e)
	}
	d.First(&l, l.ID)
	var audits int64
	if e := d.Model(&model.AuditLog{}).Where("action=? AND resource_id=?", "instance.release", fmt.Sprint(a.ID)).Count(&audits).Error; e != nil || audits != 1 {
		t.Fatal("release not audited", audits, e)
	}
	if e = s.ReleaseSelf(context.Background(), l.ID, a.ID, u.ID); e == nil {
		t.Fatal("deleted instance can still be addressed")
	}
}
