package httpserver

import (
	"authgo/internal/apidocs"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestDocumentsRequireAdminAndReturnSource(t *testing.T) {
	f := newAdminFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
	for name, source := range map[string]string{
		"protocol": apidocs.Protocol, "docker": apidocs.Docker,
		"quickstart": apidocs.Quickstart, "customer": apidocs.Customer, "offline": apidocs.Offline,
	} {
		t.Run(name, func(t *testing.T) {
			f.request(t, "GET", "/integration/"+name, "", nil, 401)
			request := httptest.NewRequest("GET", "/api/v1/admin/integration/"+name, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("User-Agent", "auth-integration-test")
			request.RemoteAddr = "198.51.100.7:4567"
			recorder := httptest.NewRecorder()
			f.r.ServeHTTP(recorder, request)
			if recorder.Code != 200 || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("文档响应: %d, Cache-Control=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
			}
			var envelope map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			value := data(envelope)
			if value["text"] != source {
				t.Fatal("文档与嵌入来源不一致")
			}
		})
	}
}
