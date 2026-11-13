package dockerhub

import (
	"authgo/internal/model"
	"context"
	"net/http"
	"testing"
	"time"
)

func TestDockerSyncPreservesPayloadDisplayMetadata(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { responsePage(w, []map[string]any{good("v1.0.0")}, nil) })
	at := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	v := model.AppVersion{AppID: f.app.ID, Version: "1.0.0", Source: "docker", Encrypted: true, BuiltAt: &at}
	if e := f.dbService.db.Create(&v).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.dbService.Sync(context.Background(), f.app.ID); e != nil {
		t.Fatal(e)
	}
	got := version(t, f, "1.0.0")
	if !got.Encrypted || got.BuiltAt == nil || !got.BuiltAt.Equal(at) {
		t.Fatal(got)
	}
}
