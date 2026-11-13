package httpserver

import (
	"authgo/internal/apidocs"
	"testing"
)

func TestProtocolRequiresAdminAndReturnsSource(t *testing.T) {
	f := newAdminFixture(t)
	f.request(t, "GET", "/integration/protocol", "", nil, 401)
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	value := data(f.request(t, "GET", "/integration/protocol", token, nil, 200))
	if value["text"] != apidocs.Protocol {
		t.Fatal("protocol differs")
	}
}
