package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOptionalMaintenanceTicketFields(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	at := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	for _, g := range []Grant{{V: 2, AppKey: "app"}, {V: 2, AppKey: "app", MaintenanceUntil: &at, LatestEntitledVersion: "2.0.0"}} {
		ticket, err := EncodeTicket(g, private)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := DecodeTicket(ticket, public)
		if err != nil || (parsed.MaintenanceUntil == nil) != (g.MaintenanceUntil == nil) || parsed.LatestEntitledVersion != g.LatestEntitledVersion {
			t.Fatal(parsed, err)
		}
		parts := strings.Split(ticket, ".")
		raw, _ := B64.DecodeString(parts[0])
		var old struct {
			V      int    `json:"v"`
			AppKey string `json:"app_key"`
		}
		if !Verify(TicketDomain, raw, parts[1], public) || json.Unmarshal(raw, &old) != nil || old.AppKey != "app" {
			t.Fatal("ticket reader rejected current optional fields")
		}
	}
}
