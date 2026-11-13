package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestPortalReleasePreservesProofAndAllowsHeartbeatReacquire(t *testing.T) {
	f := setup(t)
	id, key := f.issue(t, "KEY", "FLOATING")
	f.admin(t, "POST", "/licenses/"+strconv.FormatUint(id, 10)+"/portal-password", map[string]any{"password": "portal-password"})
	c := f.client(t, strings.Repeat("1", 64))
	if _, e := c.Check(context.Background(), key); e != nil {
		t.Fatal(e)
	}
	call := func(method, path, token string, in any) map[string]any {
		raw, _ := json.Marshal(in)
		r, _ := http.NewRequest(method, f.server.URL+"/api/v1/portal"+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("portal %d %s", resp.StatusCode, body)
		}
		var out map[string]any
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		if e := d.Decode(&out); e != nil {
			t.Fatal(e)
		}
		return out["data"].(map[string]any)
	}
	token := call("POST", "/login", "", map[string]any{"license_key": key, "password": "portal-password"})["portal_token"].(string)
	rows := call("GET", "/activations", token, nil)["items"].([]any)
	found := false
	for _, v := range rows {
		row := v.(map[string]any)
		if row["kind"] == "floating" {
			call("POST", "/activations/"+row["id"].(json.Number).String()+"/release-seat", token, map[string]any{})
			found = true
			break
		}
	}
	if !found {
		t.Fatal("floating instance not found")
	}
	if _, e := c.Heartbeat(context.Background()); e != nil {
		t.Fatal(e)
	}
}
