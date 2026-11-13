package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"authgo/internal/apidocs"
	"authgo/internal/config"
	"authgo/internal/portal"
)

func TestSwaggerOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		r, err := NewRouter(config.Config{SwaggerEnabled: enabled}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/swagger", "/swagger/", "/swagger/index.html", "/swagger/openapi.json", "/swagger/openapi.yaml", "/swagger/swagger-ui.css", "/swagger/swagger-ui-bundle.js", "/swagger/initializer.js", "/swagger/missing", "/swagger/LICENSE", "/swagger/NOTICE", "/swagger/swagger-ui-bundle.js.LICENSE.txt"} {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			want := 404
			if enabled && path != "/swagger/missing" {
				want = 200
				if path == "/swagger" {
					want = 307
				}
			}
			if w.Code != want || strings.TrimSpace(w.Body.String()) == "spa" {
				t.Fatalf("enabled=%v path=%s status=%d want=%d", enabled, path, w.Code, want)
			}
			if enabled && path == "/swagger/" && (strings.Contains(w.Body.String(), "https://") || !strings.Contains(w.Body.String(), "接口文档")) {
				t.Fatal("external or missing UI")
			}
		}
	}
}

// Use the complete service fixture to check actual Gin routes, not a second manual inventory.
func TestOpenAPIContractCoverage(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	raw, err := apidocs.Files.ReadFile("generated/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct {
				Name string `json:"name"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.OpenAPI != "3.1.0" {
		t.Fatalf("not OpenAPI 3.1: %s", spec.OpenAPI)
	}
	for name, header := range map[string]string{"AdminBearer": "Authorization", "PortalBearer": "Authorization"} {
		if spec.Components.SecuritySchemes[name].Name != header {
			t.Errorf("invalid scheme %s: %+v", name, spec.Components.SecuritySchemes)
		}
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	schemas := document["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"licensing.CreateInput", "licensing.BatchInput", "catalog.ApplicationInput", "catalog.AnnouncementInput", "catalog.VersionInput", "apidocs.GatewayRequest"} {
		schema, ok := schemas[name].(map[string]any)
		if !ok {
			t.Errorf("missing input schema: %s", name)
			continue
		}
		properties, _ := schema["properties"].(map[string]any)
		if len(properties) < 3 {
			t.Errorf("empty/truncated input schema: %s", name)
		}
	}
	var checkRefs func(any)
	checkRefs = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, item := range value {
				if key == "$ref" {
					ref, _ := item.(string)
					if !strings.HasPrefix(ref, "#/components/schemas/") {
						t.Errorf("unexpected ref %s", ref)
						continue
					}
					if _, ok := schemas[strings.TrimPrefix(ref, "#/components/schemas/")]; !ok {
						t.Errorf("unresolved schema %s", ref)
					}
				} else {
					checkRefs(item)
				}
			}
		case []any:
			for _, item := range value {
				checkRefs(item)
			}
		}
	}
	checkRefs(document)
	params := regexp.MustCompile(`:([A-Za-z_][A-Za-z_0-9]*)`)
	actual := map[string]bool{}
	for _, route := range f.r.Routes() {
		// UI/static and gated Swagger namespace registrations are not API operations.
		if !strings.HasPrefix(route.Path, "/api/") && route.Path != "/healthz" {
			continue
		}
		if route.Path == "/api/v1/admin" || route.Path == "/api/v1/admin/" {
			continue
		} // Group-root placeholders are not API operations.
		path := params.ReplaceAllString(route.Path, `{$1}`)
		method := strings.ToLower(route.Method)
		actual[method+" "+path] = true
		op, ok := spec.Paths[path][method]
		if !ok {
			t.Errorf("undocumented %s %s", route.Method, path)
			continue
		}
		for _, alternatives := range op.Security {
			for name := range alternatives {
				if _, ok := spec.Components.SecuritySchemes[name]; !ok {
					t.Errorf("unresolved security %s", name)
				}
			}
		}
	}
	for path, methods := range spec.Paths {
		for method := range methods {
			if !actual[method+" "+path] {
				t.Errorf("documented route not implemented: %s %s", method, path)
			}
		}
	}
}

func TestOpenAPIInstanceReleaseSummary(t *testing.T) {
	raw, err := apidocs.Files.ReadFile("generated/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Summary string `json:"summary"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	summary := spec.Paths["/api/v1/portal/user/instances/{id}/release-seat"]["post"].Summary
	if !strings.Contains(summary, "释放本人实例席位并删除实例记录") || strings.Contains(summary, "设备") {
		t.Fatalf("instance release summary does not describe current behavior: %q", summary)
	}
}
