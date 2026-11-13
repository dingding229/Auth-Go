package apidocs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTypedResponsesDoNotShareAnonymousDataSchema(t *testing.T) {
	raw, err := Files.ReadFile("generated/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Ref string `json:"$ref"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "#/components/schemas/data\"") {
		t.Fatal("ambiguous shared data schema")
	}
	for path, want := range map[string]string{
		"/api/v1/admin/integration/quickstart": "apidocs.ProtocolTextResponse",
		"/api/v1/admin/integration/docker":     "apidocs.ProtocolTextResponse",
		"/api/v1/admin/integration/customer":   "apidocs.ProtocolTextResponse",
		"/api/v1/admin/integration/offline":    "apidocs.ProtocolTextResponse",
		"/api/v1/admin/integration/protocol":   "apidocs.ProtocolTextResponse",
		"/api/v1/portal/licenses":              "apidocs.PortalLicenseListResponse",
	} {
		got := spec.Paths[path]["get"].Responses["200"].Content["application/json"].Schema.Ref
		if got != "#/components/schemas/"+want {
			t.Errorf("%s: %s", path, got)
		}
	}
	for schema, want := range map[string]string{
		"apidocs.ProtocolTextResponse":      "apidocs.ProtocolText",
		"apidocs.WatermarkTraceResponse":    "payloadkey.WatermarkTrace",
		"apidocs.PortalLicenseListResponse": "apidocs.PortalLicenseList",
	} {
		got := spec.Components.Schemas[schema].Properties["data"].Ref
		if got != "#/components/schemas/"+want {
			t.Errorf("%s: %s", schema, got)
		}
	}
}
