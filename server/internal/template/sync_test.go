package template

import (
	"authgo/internal/model"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestExplicitSyncScopesCountsAndNoOpWrites(t *testing.T) {
	s, d, a, b := setup(t)
	ctx := context.Background()
	source, err := s.Save(ctx, a.ID, 0, input(t, `{"name":"专业版","features":{"export":true,"quota":18446744073709551615},"default_days":90,"default_max_activations":99}`))
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Save(ctx, a.ID, 0, input(t, `{"name":"基础版","features":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := []model.License{
		{AppID: a.ID, Key: "linked-changed", TemplateID: &source.ID, Features: model.JSONMap{"old": true}},
		{AppID: a.ID, Key: "linked-equal", TemplateID: &source.ID, Features: model.JSONMap{"quota": json.Number("18446744073709551615"), "export": true}},
		{AppID: a.ID, Key: "unlinked", Features: model.JSONMap{"old": true}},
		{AppID: a.ID, Key: "other-source", TemplateID: &other.ID, Features: model.JSONMap{"old": true}},
		{AppID: a.ID, Key: "trial", Type: model.LicenseTrial, TemplateID: &source.ID, Features: model.JSONMap{"trial": true}},
		{AppID: b.ID, Key: "other-app", TemplateID: &source.ID, Features: model.JSONMap{"other": true}},
		{AppID: a.ID, Key: "equal-unlinked", Features: source.Features},
	}
	if err := d.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	before := append([]model.License{}, rows...)
	if err := d.Exec("CREATE TABLE sync_writes (license_id integer); CREATE TRIGGER count_sync_writes AFTER UPDATE ON licenses BEGIN INSERT INTO sync_writes VALUES (NEW.id); END").Error; err != nil {
		t.Fatal(err)
	}
	counts, err := s.Counts(ctx, a.ID, source.ID)
	if err != nil || counts.Linked != 2 || counts.All != 5 {
		t.Fatal(counts, err)
	}
	out, err := s.Sync(ctx, a.ID, source.ID, SyncInput{Scope: "linked"})
	if err != nil || out.Count != 1 {
		t.Fatal(out, err)
	}
	check := func(index int, changed bool) {
		t.Helper()
		var got model.License
		if err := d.First(&got, rows[index].ID).Error; err != nil {
			t.Fatal(err)
		}
		original := before[index]
		if changed {
			if got.TemplateID == nil || *got.TemplateID != source.ID || got.Features["export"] != true || len(got.Features) != 2 || got.Features["quota"].(json.Number).String() != "18446744073709551615" {
				t.Fatal(got)
			}
			got.Features, got.TemplateID, got.UpdatedAt = original.Features, original.TemplateID, original.UpdatedAt
		}
		// Compare all policy fields; timestamps are checked separately via write triggers.
		got.Base, original.Base = model.Base{}, model.Base{}
		if !reflect.DeepEqual(got, original) {
			t.Fatal("sync changed unrelated fields", index, got, original)
		}
	}
	check(0, true)
	for i := 1; i < len(rows); i++ {
		check(i, false)
	}
	out, err = s.Sync(ctx, a.ID, source.ID, SyncInput{Scope: "all"})
	if err != nil || out.Count != 2 {
		t.Fatal(out, err)
	}
	// equal-unlinked is linked without being counted.
	for _, i := range []int{0, 1, 2, 3, 6} {
		check(i, true)
	}
	for _, i := range []int{4, 5} {
		check(i, false)
	}
	out, err = s.Sync(ctx, a.ID, source.ID, SyncInput{Scope: "all"})
	if err != nil || out.Count != 0 {
		t.Fatal("repeat sync must not write", out, err)
	}
	var writes int64
	if err := d.Table("sync_writes").Count(&writes).Error; err != nil || writes != 4 {
		t.Fatal("unexpected license writes", writes, err)
	}
	counts, err = s.Counts(ctx, a.ID, source.ID)
	if err != nil || counts.Linked != 5 || counts.All != 5 {
		t.Fatal(counts, err)
	}
	_, err = s.Sync(ctx, b.ID, source.ID, SyncInput{Scope: "all"})
	status(t, err, 404)
	_, err = s.Sync(ctx, a.ID, source.ID, SyncInput{Scope: "invalid"})
	status(t, err, 400)
	_, err = s.Counts(ctx, b.ID, source.ID)
	status(t, err, 404)
}

func TestSyncRollsBackAllChangesOnFailure(t *testing.T) {
	s, d, a, _ := setup(t)
	ctx := context.Background()
	source, err := s.Save(ctx, a.ID, 0, input(t, `{"name":"同步模板","features":{"new":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]model.License, 201)
	for i := range rows {
		rows[i] = model.License{AppID: a.ID, Key: fmt.Sprintf("license-%d", i), Features: model.JSONMap{"old": true}}
	}
	if err := d.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Exec(fmt.Sprintf("CREATE TRIGGER fail_sync BEFORE UPDATE ON licenses WHEN NEW.id=%d BEGIN SELECT RAISE(ABORT,'unavailable'); END", rows[len(rows)-1].ID)).Error; err != nil {
		t.Fatal(err)
	}
	out, err := s.Sync(ctx, a.ID, source.ID, SyncInput{Scope: "all"})
	if err == nil || out.Count != 0 {
		t.Fatal(out, err)
	}
	var persisted []model.License
	if err := d.Where("app_id=?", a.ID).Find(&persisted).Error; err != nil || len(persisted) != len(rows) {
		t.Fatal(len(persisted), err)
	}
	for _, got := range persisted {
		if got.TemplateID != nil || got.Features["old"] != true || len(got.Features) != 1 {
			t.Fatal("partial sync committed", got)
		}
	}
}
