package catalog

import (
	"authgo/internal/model"
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"
)

func TestReleasePayloadMetadata(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.app(t, "metadata")
	yes := true
	no := false
	v := "1.0.0"
	at := json.RawMessage(`"2026-11-08T00:00:00Z"`)
	if _, e := f.s.CreateVersion(ctx, a.ID, VersionInput{Version: &v, Encrypted: &yes}); e == nil {
		t.Fatal("missing built_at accepted")
	}
	r, e := f.s.CreateVersion(ctx, a.ID, VersionInput{Version: &v, Encrypted: &yes, BuiltAt: at})
	if e != nil || !r.Encrypted || r.BuiltAt == nil {
		t.Fatal(r, e)
	}
	if e = f.db.Model(&model.AppVersion{}).Where("id=?", r.ID).Update("source", "github").Error; e != nil {
		t.Fatal(e)
	}
	rows, _, e := f.s.ListVersions(ctx, a.ID, query(t, url.Values{}))
	if e != nil || len(rows) != 1 || !rows[0].Encrypted {
		t.Fatal(rows, e)
	}
	r, e = f.s.UpdateVersion(ctx, r.ID, VersionInput{Changelog: ptr("edited")})
	if e != nil || r.BuiltAt == nil || !r.Encrypted {
		t.Fatal("patch lost metadata", e)
	}
	if _, e = f.s.UpdateVersion(ctx, r.ID, VersionInput{BuiltAt: json.RawMessage(`"invalid"`)}); e == nil {
		t.Fatal("invalid time accepted")
	}
	r, e = f.s.UpdateVersion(ctx, r.ID, VersionInput{Encrypted: &no})
	if e != nil || r.Encrypted || r.BuiltAt != nil {
		t.Fatal("clear failed", e)
	}
}

func TestConfirmedBuildMetadataIsReadOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.app(t, "confirmed")
	built := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	row := model.AppVersion{AppID: a.ID, Version: "1.0.0", Encrypted: true, BuildVerified: true, BuiltAt: &built}
	if err := f.db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	for _, at := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`"invalid"`), json.RawMessage(`"2026-11-16T00:00:00Z"`)} {
		no := false
		disabled := true
		r, err := f.s.UpdateVersion(ctx, row.ID, VersionInput{Encrypted: &no, BuiltAt: at, Changelog: ptr("edited"), Disabled: &disabled})
		if err != nil || !r.Encrypted || !r.BuildVerified || r.BuiltAt == nil || !r.BuiltAt.Equal(built) || r.Changelog != "edited" || !r.Disabled {
			t.Fatal("confirmed metadata changed or other fields rejected", r, err)
		}
	}
	r, err := f.s.GetVersion(ctx, row.ID)
	if err != nil || !r.BuildVerified {
		t.Fatal("get lost confirmation", r, err)
	}
	rows, _, err := f.s.ListVersions(ctx, a.ID, query(t, url.Values{}))
	if err != nil || len(rows) != 1 || !rows[0].BuildVerified {
		t.Fatal("list lost confirmation", rows, err)
	}
}
