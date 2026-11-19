package dockerhub

import (
	"authgo/internal/model"
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadTagArchitecturesAcrossPages(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			v := good("v1.2.3")
			v["images"] = []map[string]any{
				{"architecture": "arm", "os": "linux", "variant": "v7"},
				{"architecture": "unknown", "os": "unknown"},
				{"architecture": "", "os": "linux"},
				{"architecture": "amd64", "os": "linux", "variant": nil, "digest": "sha256:ignored", "status": "active"},
			}
			responsePage(w, []map[string]any{v, good("2.0.0")}, "more")
			return
		}
		v := good("1.2.3")
		v["images"] = []tagImage{
			{Architecture: "arm64", OS: "linux"},
			{Architecture: "amd64", OS: "linux"},
			{Architecture: "amd64", OS: "windows"},
		}
		empty := good("3.0.0")
		empty["images"] = []tagImage{}
		responsePage(w, []map[string]any{v, empty}, nil)
	})
	image, err := Image(f.app.DockerImage)
	if err != nil {
		t.Fatal(err)
	}
	snap, failure := f.dbService.read(context.Background(), image, false)
	if failure != nil || !snap.complete || len(snap.versions) != 3 {
		t.Fatal(snap, failure)
	}
	v := snap.versions["1.2.3"]
	if v.Tag != "1.2.3" || v.Architectures != "amd64,arm/v7,arm64,windows/amd64" {
		t.Fatal(v)
	}
	if snap.versions["2.0.0"].Architectures != "" || snap.versions["3.0.0"].Architectures != "" {
		t.Fatal("missing or empty images should not invent architectures", snap.versions)
	}
}

func TestSyncUpdatesArchitectureForDockerAndManualVersions(t *testing.T) {
	var phase atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		docker, manual := good("1.0.0"), good("2.0.0")
		switch phase.Load() {
		case 0:
			docker["images"] = []tagImage{{Architecture: "arm64", OS: "linux"}}
			manual["images"] = []tagImage{{Architecture: "amd64", OS: "linux"}}
		case 1:
			docker["images"] = []tagImage{{Architecture: "amd64", OS: "linux"}}
			manual["images"] = []tagImage{{Architecture: "arm", OS: "linux", Variant: "v7"}}
		case 2:
			manual["images"] = []tagImage{{Architecture: "unknown", OS: "unknown"}}
		}
		responsePage(w, []map[string]any{docker, manual}, nil)
	})
	published := f.now().Add(-time.Hour)
	manual := model.AppVersion{AppID: f.app.ID, Version: "2.0.0", Source: "manual", PublishedAt: &published, Changelog: "manual notes", Disabled: true}
	if err := f.dbService.db.Create(&manual).Error; err != nil {
		t.Fatal(err)
	}
	for i, want := range [][2]string{{"arm64", "amd64"}, {"amd64", "arm/v7"}, {"amd64", "arm/v7"}} {
		phase.Store(int32(i))
		if err := f.dbService.Sync(context.Background(), f.app.ID); err != nil {
			t.Fatal(err)
		}
		a, b := version(t, f, "1.0.0"), version(t, f, "2.0.0")
		if a.Source != "docker" || a.Architectures != want[0] || b.Architectures != want[1] {
			t.Fatalf("phase %d: Docker=%q manual=%q; want %v", i, a.Architectures, b.Architectures, want)
		}
		if b.ID != manual.ID || b.Source != "manual" || b.Changelog != manual.Changelog || !b.Disabled || b.PublishedAt == nil || !b.PublishedAt.Equal(published) {
			t.Fatal("architecture sync changed manual metadata", b)
		}
	}
}
