package licensing

import (
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestIssuanceRecordsTemplateWithoutReplacingFeatures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	source := model.FeatureTemplate{AppID: f.app.ID, Name: "专业版", Features: model.JSONMap{"export": true}}
	if err := f.db.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	in := CreateInput{AppID: f.app.ID, UserID: &f.user.ID, TemplateID: &source.ID, Features: json.RawMessage(`{"export":false,"quota":9007199254740993}`)}
	one, err := f.s.Create(ctx, in)
	if err != nil || one.TemplateID == nil || *one.TemplateID != source.ID || one.TemplateName != source.Name || one.Features["export"] != false {
		t.Fatal(one, err)
	}
	batch, err := f.s.Batch(ctx, BatchInput{CreateInput: in, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	rows, total, err := f.s.List(ctx, Filter{BatchID: batch.BatchID, Query: response.ListQuery{Page: response.Page{Number: 1, Size: 20}, SortBy: "id"}})
	if err != nil || total != 3 {
		t.Fatal(rows, total, err)
	}
	for _, row := range rows {
		if row.TemplateID == nil || *row.TemplateID != source.ID || row.TemplateName != source.Name || row.Features["export"] != false || row.Features["quota"].(json.Number).String() != "9007199254740993" {
			t.Fatal(row)
		}
	}
	in.Type = ptr(model.LicenseTrial)
	trial, err := f.s.Create(ctx, in)
	if err != nil || trial.TemplateID != nil || trial.TemplateName != "" {
		t.Fatal("trial recorded source", trial, err)
	}
}

func TestIssuanceRejectsOtherSoftwareTemplate(t *testing.T) {
	f := newFixture(t)
	other := model.Application{Name: "其他软件", AppKey: "other"}
	if err := f.db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	source := model.FeatureTemplate{AppID: other.ID, Name: "其他模板", Features: model.JSONMap{}}
	if err := f.db.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	in := CreateInput{AppID: f.app.ID, UserID: &f.user.ID, TemplateID: &source.ID}
	_, err := f.s.Create(context.Background(), in)
	status(t, err, 400)
	_, err = f.s.Batch(context.Background(), BatchInput{CreateInput: in, Count: 3})
	status(t, err, 400)
	in.TemplateID = ptr(uint64(0))
	_, err = f.s.Create(context.Background(), in)
	status(t, err, 400)
}

func TestApplyTemplateChangesOnlyFeaturesAndSource(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)
	source := model.FeatureTemplate{AppID: f.app.ID, Name: "新功能", Features: model.JSONMap{"export": true, "quota": json.Number("18446744073709551615")}, DefaultMaxActivations: ptr(99), DefaultDays: ptr(365), DefaultMaintenanceDays: ptr(365)}
	if err := f.db.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	until := f.clock.now().AddDate(0, 1, 0)
	if err := f.db.Model(&model.License{}).Where("id=?", created.ID).Update("maintenance_until", until).Error; err != nil {
		t.Fatal(err)
	}
	var before, after model.License
	if err := f.db.First(&before, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	out, err := f.s.ApplyTemplate(ctx, created.ID, TemplateInput{TemplateID: source.ID})
	if err != nil || out.TemplateID == nil || *out.TemplateID != source.ID || out.TemplateName != source.Name || out.Features["export"] != true || len(out.Features) != 2 {
		t.Fatal(out, err)
	}
	if err := f.db.First(&after, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	after.Features, after.TemplateID, after.UpdatedAt = before.Features, before.TemplateID, before.UpdatedAt
	if !reflect.DeepEqual(before, after) {
		t.Fatal("template changed unrelated fields", before, after)
	}
	if err := f.db.Delete(&source).Error; err != nil {
		t.Fatal(err)
	}
	detail, err := f.s.Get(ctx, created.ID)
	if err != nil || detail.TemplateID != nil || detail.TemplateName != "" || detail.Features["export"] != true || detail.Features["quota"].(json.Number).String() != "18446744073709551615" {
		t.Fatal("delete lost features or retained source", detail, err)
	}
}

func TestApplyTemplateRejectsTrialAndOtherSoftware(t *testing.T) {
	f := newFixture(t)
	created := f.create(t)
	other := model.Application{Name: "其他软件", AppKey: "other"}
	if err := f.db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	source := model.FeatureTemplate{AppID: other.ID, Name: "其他模板", Features: model.JSONMap{}}
	if err := f.db.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	_, err := f.s.ApplyTemplate(context.Background(), created.ID, TemplateInput{TemplateID: source.ID})
	status(t, err, 400)
	if err := f.db.Model(&model.License{}).Where("id=?", created.ID).Update("type", model.LicenseTrial).Error; err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ApplyTemplate(context.Background(), created.ID, TemplateInput{TemplateID: source.ID})
	status(t, err, 400)
	if !strings.Contains(err.Error(), "试用授权不能套用功能模板") {
		t.Fatal(err)
	}
}
