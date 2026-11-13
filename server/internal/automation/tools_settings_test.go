package automation

import (
	"authgo/internal/model"
	"context"
	"encoding/json"
	"testing"
)

func TestToolsSettingsValidation(t *testing.T) {
	base := Settings{SiteName: "test", NotificationRetentionDays: 30, IPQueryRate: 1, IPBurst: 1, LicenseRate: 1, LicenseBurst: 1, LogRetentionDays: 30, SMTP: SMTP{Mode: "plain", Port: 587}}
	for _, pair := range [][2]string{{"team/authgo-tools", "v1.0.0"}, {"registry.example.com/team/tools", "1.2.3"}, {"localhost:5000/team/tools", "dev"}, {"", ""}} {
		v := base
		v.ToolsImage = pair[0]
		v.ToolsVersion = pair[1]
		if e := validateSettings(&v); e != nil {
			t.Fatal(pair, e)
		}
	}
	for _, pair := range [][2]string{{"tools", "v1"}, {"team/tools:latest", "v1"}, {"https://host/team/tools", "v1"}, {"user:password@host/team/tools", "v1"}, {"team/tools", ""}, {"", "v1"}, {"team/tools", "bad tag"}, {"team/tools\nRUN x", "v1"}} {
		v := base
		v.ToolsImage = pair[0]
		v.ToolsVersion = pair[1]
		if e := validateSettings(&v); e == nil {
			t.Fatal("unsafe tools setting", pair)
		}
	}
}
func TestToolsSettingsPersistAndPatch(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	image, version := "registry.example.com/team/tools", "v1.2.3"
	got, e := f.s.UpdateSettings(ctx, SettingsInput{ToolsImage: &image, ToolsVersion: &version})
	if e != nil || got.ToolsImage != image || got.ToolsVersion != version {
		t.Fatal(got, e)
	}
	site := "changed"
	got, e = f.s.UpdateSettings(ctx, SettingsInput{SiteName: &site})
	if e != nil || got.ToolsVersion != version {
		t.Fatal("unrelated patch lost tool", e)
	}
	var stored model.Setting
	if e = f.db.First(&stored, "key=?", "system.v1").Error; e != nil {
		t.Fatal(e)
	}
	var decoded Settings
	if e = json.Unmarshal([]byte(stored.Value), &decoded); e != nil || decoded.ToolsImage != image {
		t.Fatal("not persisted", e)
	}
}
