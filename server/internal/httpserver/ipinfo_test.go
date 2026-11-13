package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"authgo/internal/apidocs"
	"authgo/internal/auth"
	"authgo/internal/config"
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"authgo/internal/portal"
)

func TestIPInfoEndpointsEnrichmentAndDisabledFields(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	userToken := userPassword(t, f)
	token := f.password(t)
	activation := model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "ipinfo-instance", Token: "test-session", Status: "active", FirstIP: "8.8.8.8", LastIP: "8.8.8.8"}
	if e := f.db.Create(&activation).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Create(&model.VerifyLog{LicenseID: &f.license.ID, IP: "8.8.8.8", Code: "OK", Success: true, CreatedAt: f.clock.now()}).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Create(&model.AuditLog{Action: "ipinfo.fixture", IP: "8.8.8.8", Details: map[string]any{}}).Error; e != nil {
		t.Fatal(e)
	}
	type view struct {
		name string
		read func() map[string]any
		rows func(map[string]any) []any
	}
	items := func(d map[string]any) []any { return d["items"].([]any) }
	views := []view{
		{"verification logs", func() map[string]any { return data(f.request(t, "GET", "/verify-logs", owner, nil, 200)) }, items},
		{"audit logs", func() map[string]any {
			return data(f.request(t, "GET", "/audit-logs?action=ipinfo.fixture", owner, nil, 200))
		}, items},
		{"instances", func() map[string]any { return data(f.request(t, "GET", "/activations", owner, nil, 200)) }, items},
		{"license activations", func() map[string]any {
			return data(f.request(t, "GET", fmt.Sprintf("/licenses/%d/activations", f.license.ID), owner, nil, 200))
		}, items},
		{"license detail", func() map[string]any {
			return data(f.request(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), owner, nil, 200))
		}, func(d map[string]any) []any { return d["activations"].([]any) }},
		{"portal activations", func() map[string]any { return data(f.p(t, "GET", "/activations", token, nil, "OK")) }, items},
		{"portal user instances", func() map[string]any { return data(f.p(t, "GET", "/user/instances", userToken, nil, "OK")) }, items},
		{"portal logs", func() map[string]any { return data(f.p(t, "GET", "/logs", token, nil, "OK")) }, items},
	}
	baseline := make([]map[string]any, len(views))
	for i, v := range views {
		baseline[i] = v.read()
	}
	ips, e := ipinfo.New(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ips.Close() })
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithCatalog(f.catalog), WithLicensing(f.licensing), WithClient(f.service), WithAutomation(f.notifications), WithPortal(f.portalService), WithIPInfo(ips))
	if e != nil {
		t.Fatal(e)
	}
	for i, v := range views {
		if !reflect.DeepEqual(baseline[i], v.read()) {
			t.Fatalf("disabled changed %s", v.name)
		}
	}
	f.request(t, "GET", "/system/ip-info", "", nil, 401)
	for _, path := range []string{"/system/ip-info/enable", "/system/ip-info/update", "/system/ip-info/city"} {
		f.request(t, "POST", path, "", nil, 401)
	}
	f.request(t, "DELETE", "/system/ip-info", token, nil, 401)
	requestUpload := func(kind, name string, multi bool, want int) {
		t.Helper()
		raw, e := os.ReadFile("../ipinfo/testdata/" + name + ".mmdb")
		if e != nil {
			t.Fatal(e)
		}
		content := "application/octet-stream"
		if multi {
			var b bytes.Buffer
			w := multipart.NewWriter(&b)
			part, e := w.CreateFormFile("file", "../../outside.mmdb")
			if e != nil {
				t.Fatal(e)
			}
			_, _ = part.Write(raw)
			_ = w.Close()
			raw = b.Bytes()
			content = w.FormDataContentType()
		}
		req := httptest.NewRequest("POST", "/api/v1/admin/system/ip-info/"+kind, bytes.NewReader(raw))
		req.Header.Set("Content-Type", content)
		req.Header.Set("Authorization", "Bearer "+owner)
		out := httptest.NewRecorder()
		f.r.ServeHTTP(out, req)
		if out.Code != want {
			t.Fatalf("upload: %d %s", out.Code, out.Body.String())
		}
	}
	requestUpload("city", "city", true, 200)
	requestUpload("asn", "asn", false, 200)
	status := data(f.request(t, "GET", "/system/ip-info", owner, nil, 200))
	if status["enabled"] != true || status["city"].(map[string]any)["source"] != "upload" {
		t.Fatal(status)
	}
	for i, v := range views {
		got := v.read()
		rows := v.rows(got)
		if len(rows) == 0 {
			t.Fatalf("%s empty", v.name)
		}
		for _, raw := range rows {
			row := raw.(map[string]any)
			info, ok := row["ip_info"].(map[string]any)
			if !ok || info["city"] != "上海" || fmt.Sprint(info["asn"]) != "64500" {
				t.Fatalf("%s: %+v", v.name, row)
			}
			delete(row, "ip_info")
		}
		if !reflect.DeepEqual(got, baseline[i]) {
			t.Fatalf("changed existing %s fields: %+v vs %+v", v.name, got, baseline[i])
		}
		if strings.HasPrefix(v.name, "portal") {
			raw, _ := json.Marshal(v.read())
			if bytes.Contains(raw, []byte("8.8.8.8")) {
				t.Fatalf("raw IP exposed: %s", raw)
			}
		}
	}
	requestUpload("city", "asn", false, 400)
	if ips.Lookup("8.8.8.8").City != "上海" {
		t.Fatal("bad upload replaced old")
	}
	f.request(t, "DELETE", "/system/ip-info", owner, nil, 200)
	for i, v := range views {
		if !reflect.DeepEqual(baseline[i], v.read()) {
			t.Fatalf("delete changed %s", v.name)
		}
	}
	for _, action := range []string{"ipinfo.upload", "ipinfo.delete"} {
		var n int64
		if e := f.db.Model(&model.AuditLog{}).Where("action=? AND status_code=200", action).Count(&n).Error; e != nil || n == 0 {
			t.Fatalf("audit %s: %d %v", action, n, e)
		}
	}
	raw, e := apidocs.Files.ReadFile("generated/swagger.json")
	if e != nil {
		t.Fatal(e)
	}
	var spec struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if e = json.Unmarshal(raw, &spec); e != nil {
		t.Fatal(e)
	}
	for envelope, dataType := range map[string]string{"IPInfoResponse": "ipinfo.Status", "AuditLogResponse": "apidocs.AuditLogList", "VerifyLogResponse": "apidocs.VerifyLogList", "PortalActivationResponse": "apidocs.PortalActivationList", "PortalVerificationLogResponse": "apidocs.PortalVerificationLogList", "UserInstanceListResponse": "apidocs.usercenterUserInstanceList", "ActivationListResponse": "apidocs.ActivationList", "LicenseDetailResponse": "licensing.Detail"} {
		if ref := spec.Components.Schemas["apidocs."+envelope].Properties["data"]["$ref"]; ref != "#/components/schemas/"+dataType {
			t.Fatalf("wrong %s data schema: %v", envelope, ref)
		}
	}
	for _, route := range []struct{ path, method string }{{"/api/v1/admin/system/ip-info", "get"}, {"/api/v1/admin/system/ip-info", "delete"}, {"/api/v1/admin/system/ip-info/enable", "post"}, {"/api/v1/admin/system/ip-info/update", "post"}, {"/api/v1/admin/system/ip-info/{kind}", "post"}} {
		if spec.Paths[route.path][route.method] == nil {
			t.Fatal("missing OpenAPI", route)
		}
	}
}

func TestPortalSessionExposesOnlyPublicIPAttribution(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	userToken := userPassword(t, f)
	token := f.password(t)
	dir := t.TempDir()
	ips, e := ipinfo.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = ips.Close() }()
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	configure := func() {
		t.Helper()
		f.r, e = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithPortal(f.portalService), WithIPInfo(ips))
		if e != nil {
			t.Fatal(e)
		}
	}
	configure()
	check := func(want bool) {
		t.Helper()
		for _, credential := range []string{token, userToken} {
			view := data(f.p(t, "GET", "/session", credential, nil, "OK"))
			if want {
				if view["ip_info_dbip"] != true {
					t.Fatal(view)
				}
			} else if _, ok := view["ip_info_dbip"]; ok {
				t.Fatal("disabled/uploaded library must omit attribution", view)
			}
			for k := range view {
				if k != "scope" && k != "selected_license_id" && k != "ip_info_dbip" {
					t.Fatal("private setting exposed", k)
				}
			}
		}
	}
	check(false)
	raw, e := os.ReadFile("../ipinfo/testdata/city.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	if e = ips.Upload(context.Background(), "city", bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	check(false)
	if e = ips.Close(); e != nil {
		t.Fatal(e)
	}
	statePath := filepath.Join(dir, "ipdb", "state.json")
	stateRaw, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	var state map[string]any
	if e = json.Unmarshal(stateRaw, &state); e != nil {
		t.Fatal(e)
	}
	state["city"].(map[string]any)["source"] = "db-ip"
	stateRaw, e = json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(statePath, stateRaw, 0600); e != nil {
		t.Fatal(e)
	}
	ips, e = ipinfo.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	configure()
	check(true)
	if e = ips.Delete(context.Background()); e != nil {
		t.Fatal(e)
	}
	check(false)
}
