package catalog

import (
	"authgo/internal/model"
	"context"
	"encoding/json"
	"net/url"
	"testing"
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
