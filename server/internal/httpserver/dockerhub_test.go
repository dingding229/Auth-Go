package httpserver

import (
	"authgo/internal/dockerhub"
	"authgo/internal/model"
	"authgo/internal/portal"
	"testing"
	"time"
)

func TestPortalDockerPullIsSelectedLicenseScopedAndClearStopsUpdates(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	if err := f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "org/own-app").Error; err != nil {
		t.Fatal(err)
	}
	at := f.clock.now().Add(-time.Hour)
	docker := model.AppVersion{AppID: f.app.ID, Version: "3.0.0", Source: "docker", PublishedAt: &at}
	manual := model.AppVersion{AppID: f.app.ID, Version: "2.0.0", Source: "manual", PublishedAt: &at}
	for _, v := range []*model.AppVersion{&docker, &manual} {
		if err := f.db.Create(v).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.Model(&dockerhub.State{}).Where("app_id=?", f.app.ID).Updates(map[string]any{"tags_json": `{"3.0.0":"v3.0.0"}`}).Error; err != nil {
		t.Fatal(err)
	}
	token := f.password(t)
	f.p(t, "GET", "/update?os=linux&arch=amd64", "", nil, "PORTAL_UNAUTHORIZED")
	value := data(f.p(t, "GET", "/update?os=invalid&arch=invalid&app_id=9999&license_id=9999", token, nil, "OK"))
	if value["docker_pull"] != "docker pull org/own-app:v3.0.0" || value["version"] != "3.0.0" {
		t.Fatal(value)
	}
	if _, exists := value["download_url"]; exists {
		t.Fatal("Docker view returned download link")
	}
	f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("status", "suspended")
	f.p(t, "GET", "/update", token, nil, "LICENSE_SUSPENDED")
	f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("status", "unused")
	f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "")
	value = data(f.p(t, "GET", "/update?os=linux&arch=amd64", token, nil, "OK"))
	if value["available"] != false {
		t.Fatal(value)
	}
	var n int64
	f.db.Model(&model.AppVersion{}).Where("id=? AND withdrawn=0", docker.ID).Count(&n)
	if n != 1 {
		t.Fatal("clearing image changed old Docker row")
	}
}
