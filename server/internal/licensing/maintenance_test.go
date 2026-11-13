package licensing

import (
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestIssueBatchRenewAndModifyMaintenance(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	days := 30
	in := CreateInput{AppID: f.app.ID, UserID: &f.user.ID, ValidityRule: ptr("fixed_days"), DurationDays: ptr(30), Input: maintenance.Input{MaintenanceDays: &days}}
	l, err := f.s.Create(ctx, in)
	if err != nil || l.MaintenanceUntil == nil || !l.MaintenanceUntil.Equal(f.clock.now().AddDate(0, 0, 30)) {
		t.Fatal(l, err)
	}
	batch, err := f.s.Batch(ctx, BatchInput{CreateInput: in, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	var rows []model.License
	if err := f.db.Where("batch_id=?", batch.BatchID).Find(&rows).Error; err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, r := range rows {
		if r.MaintenanceUntil == nil || !r.MaintenanceUntil.Equal(*l.MaintenanceUntil) {
			t.Fatal(r)
		}
	}
	renewed, err := f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(2)})
	if err != nil || !renewed.MaintenanceUntil.Equal(*l.MaintenanceUntil) {
		t.Fatal("renewal implicitly extended maintenance", renewed, err)
	}
	days = 60
	renewed, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(2), Input: maintenance.Input{MaintenanceDays: &days}})
	if err != nil || !renewed.MaintenanceUntil.Equal(f.clock.now().AddDate(0, 0, 60)) {
		t.Fatal(renewed, err)
	}
	renewed, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(2), Input: maintenance.Input{MaintenanceUntil: json.RawMessage("null")}})
	if err != nil || renewed.MaintenanceUntil != nil {
		t.Fatal(renewed, err)
	}
	svc := maintenance.New(f.db, f.clock.now)
	at := f.clock.now().Add(24 * time.Hour)
	raw, _ := json.Marshal(at)
	got, err := svc.Update(ctx, l.ID, maintenance.Input{MaintenanceUntil: raw})
	if err != nil || got == nil || !got.Equal(at) {
		t.Fatal(got, err)
	}
	if _, err = svc.Update(ctx, l.ID, maintenance.Input{MaintenanceDays: ptr(0)}); err != nil {
		t.Fatal(err)
	}
	var stored model.License
	f.db.First(&stored, l.ID)
	if stored.MaintenanceUntil != nil {
		t.Fatal(stored)
	}
	for _, bad := range []maintenance.Input{{MaintenanceDays: ptr(-1)}, {MaintenanceDays: ptr(36501)}, {MaintenanceDays: ptr(1), MaintenanceUntil: raw}, {MaintenanceUntil: json.RawMessage(`"bad"`)}} {
		if _, _, err := bad.Resolve(f.clock.now()); err == nil {
			t.Fatal("invalid maintenance accepted", bad)
		}
	}
}
