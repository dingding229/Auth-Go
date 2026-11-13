package template

import (
	"authgo/internal/apperror"
	"authgo/internal/db"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"testing"
	"time"
)

func setup(t *testing.T) (*Service, *gorm.DB, model.Application, model.Application) {
	t.Helper()
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	p, _ := d.DB()
	t.Cleanup(func() { p.Close() })
	a := model.Application{Name: "one", AppKey: "one"}
	b := model.Application{Name: "two", AppKey: "two"}
	if e = d.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	if e = d.Create(&b).Error; e != nil {
		t.Fatal(e)
	}
	return New(d), d, a, b
}
func input(t *testing.T, s string) Input {
	t.Helper()
	var in Input
	if e := json.Unmarshal([]byte(s), &in); e != nil {
		t.Fatal(e)
	}
	return in
}
func status(t *testing.T, e error, want int) {
	t.Helper()
	var a *apperror.Error
	if !errors.As(e, &a) || a.Status != want {
		t.Fatalf("%v want %d", e, want)
	}
}
func TestCRUDCopiesAndScopedAccess(t *testing.T) {
	s, d, a, b := setup(t)
	ctx := context.Background()
	x, e := s.Save(ctx, a.ID, 0, input(t, `{"name":"专业版","features":{"export":true,"quota":12345678901234567890},"default_max_activations":5,"default_days":30,"default_maintenance_days":0}`))
	if e != nil {
		t.Fatal(e)
	}
	items, n, e := s.List(ctx, a.ID, response.Page{Number: 1, Size: 1})
	if e != nil || n != 1 || len(items) != 1 {
		t.Fatal(items, n, e)
	}
	if x.Features["quota"].(json.Number).String() != "12345678901234567890" {
		t.Fatal(x)
	}
	// Issuance stores the form values as an independent JSON object, not template IDs.
	l := model.License{AppID: a.ID, Key: "snapshot", Features: x.Features}
	if e = d.Create(&l).Error; e != nil {
		t.Fatal(e)
	}
	_, e = s.Save(ctx, b.ID, x.ID, input(t, `{"name":"other"}`))
	status(t, e, 404)
	status(t, s.Delete(ctx, b.ID, x.ID), 404)
	_, e = s.Save(ctx, a.ID, 0, input(t, `{"name":"专业版","features":{}}`))
	status(t, e, 409)
	// Names only have to be unique within a software.
	if _, e = s.Save(ctx, b.ID, 0, input(t, `{"name":"专业版","features":{}}`)); e != nil {
		t.Fatal(e)
	}
	y, e := s.Save(ctx, a.ID, x.ID, input(t, `{"features":{"export":false},"default_max_activations":null}`))
	if e != nil || y.DefaultMaxActivations != nil || *y.DefaultDays != 30 {
		t.Fatal(y, e)
	}
	if e = s.Delete(ctx, a.ID, x.ID); e != nil {
		t.Fatal(e)
	}
	var got model.License
	if e = d.First(&got, l.ID).Error; e != nil {
		t.Fatal(e)
	}
	if got.Features["export"] != true || got.Features["quota"].(json.Number).String() != "12345678901234567890" {
		t.Fatal("issued license changed", got.Features)
	}
}
func TestInputAndReferencedDeletion(t *testing.T) {
	s, d, a, _ := setup(t)
	ctx := context.Background()
	for _, raw := range []string{`{"name":"","features":{}}`, `{"name":"x","features":[]}`, `{"name":"x","features":null}`, `{"name":"x","features":5}`, `{"name":"x","features":{ },"default_days":0}`, `{"name":"x","features":{ },"default_max_activations":1.5}`, `{"name":"x","features":{ },"default_maintenance_days":-1}`} {
		_, e := s.Save(ctx, a.ID, 0, input(t, raw))
		status(t, e, 400)
	}
	x, e := s.Save(ctx, a.ID, 0, input(t, `{"name":"used","features":{}}`))
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Model(&a).Update("trial_template_id", x.ID).Error; e != nil {
		t.Fatal(e)
	}
	e = s.Delete(ctx, a.ID, x.ID)
	status(t, e, 409)
	if e.(*apperror.Error).Message != "此模板正用于试用，请先在试用设置中更换" {
		t.Fatal(e)
	}
	// Software deletion also follows existing RESTRICT policy.
	if e = d.Delete(&a).Error; e == nil {
		t.Fatal("software with templates deleted")
	}
	if e = d.Model(&a).Update("trial_template_id", nil).Error; e != nil {
		t.Fatal(e)
	}
	if e = s.Delete(ctx, a.ID, x.ID); e != nil {
		t.Fatal(e)
	}
}
