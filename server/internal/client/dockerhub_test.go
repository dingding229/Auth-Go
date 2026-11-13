package client

import (
	"authgo/internal/model"
	"context"
	"testing"
	"time"
)

func TestPublicVersionIncludesDockerWithoutHostedDownloadLink(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	if err := f.db.Model(&model.Application{}).Where("id = ?", f.app.ID).Update("docker_image", "example-org/example-app").Error; err != nil {
		t.Fatal(err)
	}
	at := f.clock.now().Add(-time.Hour)
	for _, v := range []model.AppVersion{
		{AppID: f.app.ID, Version: "1.0.0", Source: "manual", PublishedAt: &at},
		{AppID: f.app.ID, Version: "2.0.0", Source: "docker", PublishedAt: &at},
		{AppID: f.app.ID, Version: "3.0.0", Source: "docker", PublishedAt: &at, Withdrawn: true},
		{AppID: f.app.ID, Version: "4.0.0", Source: "docker", PublishedAt: &at, Disabled: true},
	} {
		if err := f.db.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
	}
	out, err := f.service.latestVersion(context.Background(), f.app.ID, f.clock.now())
	if err != nil || out.Version != "2.0.0" || out.Source != "docker" {
		t.Fatal(out, err)
	}
}

func TestLatestVersionExcludesDockerAfterImageCleared(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	at := f.clock.now().Add(-time.Hour)
	manual := model.AppVersion{AppID: f.app.ID, Version: "1.0.0", Source: "manual", PublishedAt: &at}
	docker := model.AppVersion{AppID: f.app.ID, Version: "2.0.0", Source: "docker", PublishedAt: &at}
	for _, v := range []*model.AppVersion{&manual, &docker} {
		if err := f.db.Create(v).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		image string
		want  string
	}{
		{image: "example-org/example-app", want: "2.0.0"},
		{image: "", want: "1.0.0"},
	} {
		if err := f.db.Model(&model.Application{}).Where("id = ?", f.app.ID).Update("docker_image", tc.image).Error; err != nil {
			t.Fatal(err)
		}
		out, err := f.service.latestVersion(context.Background(), f.app.ID, f.clock.now())
		if err != nil || out.Version != tc.want {
			t.Fatalf("image %q: version = %+v, error = %v; want %s", tc.image, out, err, tc.want)
		}
	}
	var retained model.AppVersion
	if err := f.db.First(&retained, docker.ID).Error; err != nil {
		t.Fatal(err)
	}
	if retained.Withdrawn || retained.Source != "docker" || retained.Version != "2.0.0" || retained.PublishedAt == nil || !retained.PublishedAt.Equal(at) {
		t.Fatalf("clearing image changed retained Docker version: %+v", retained)
	}
}
