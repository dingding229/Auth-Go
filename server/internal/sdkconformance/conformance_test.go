package sdkconformance_test

// TestSDKConformanceHost runs only in the opt-in official-image SDK suite. It
// uses the production gateway/policy/database and persisted DockerHub metadata.
// This host is test-only; it does not recreate removed product routes.
import (
	"authgo/internal/catalog"
	"authgo/internal/channel"
	"authgo/internal/client"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/db"
	"authgo/internal/dockerhub"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/trial"
	"authgo/sdk/wire"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm/clause"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSDKConformanceHost(t *testing.T) {
	if os.Getenv("AUTHGO_SDK_CONFORMANCE") != "1" {
		t.Skip("opt-in SDK conformance host")
	}
	database, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := database.DB()
	defer pool.Close()
	if e = db.Migrate(database); e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	cat, _ := catalog.NewService(database, master)
	ls := licensing.NewService(database)
	box, _ := cryptoutil.NewCipher(master)
	keys, _ := channel.New(database, master)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var timeOffset atomic.Int64
	var gatewayCalls atomic.Uint64
	serviceOptions := client.Options{Now: func() time.Time { return time.Now().Add(time.Duration(timeOffset.Load()) * time.Second) }, IPRate: 100000, LicenseRate: 100000, IPBurst: 100000, LicenseBurst: 100000}
	clients, e := client.NewService(database, master, log, client.Options{Now: serviceOptions.Now, IPRate: 100000, LicenseRate: 100000, IPBurst: 100000, LicenseBurst: 100000})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { clients.Close(context.Background()) }()
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	clients.Register(router)
	var mu sync.Mutex
	mode := ""
	var app model.Application
	var fixtureTime time.Time
	var licenses []licensing.LicenseInfo
	var user model.EndUser
	mux := http.NewServeMux()
	mux.HandleFunc("/fixture", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		mode = ""
		timeOffset.Store(0)
		fixtureTime = time.Now().UTC().Truncate(time.Second)
		name := "SDK conformance"
		image := "authgo-contract/conformance"
		a, err := cat.CreateApplication(r.Context(), catalog.ApplicationInput{Name: &name, DockerImage: &image})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		app = model.Application{}
		database.First(&app, a.ID)
		user = model.EndUser{Name: "SDK user", Status: "active"}
		database.Create(&user)
		licenses = nil
		for i := 0; i < 3; i++ {
			l, err := ls.Create(r.Context(), licensing.CreateInput{AppID: app.ID, UserID: &user.ID})
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			database.Model(&model.License{}).Where("id=?", l.ID).Updates(map[string]any{"verify_methods": `["KEY","FLOATING"]`, "max_activations": 1})
			licenses = append(licenses, l)
		}
		config, _ := cat.ConnectionConfig(r.Context(), app.ID, "http://127.0.0.1:18091")
		published := fixtureTime.Add(-time.Hour)
		if err := database.Create(&model.AppVersion{AppID: app.ID, Version: "2.1.0", Source: "docker", PublishedAt: &published, Changelog: "DockerHub conformance"}).Error; err != nil {
			http.Error(w, "fixture version", 500)
			return
		}
		if err := database.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "app_id"}}, DoUpdates: clause.AssignmentColumns([]string{"image", "tags_json", "next_sync_at"})}).Create(&dockerhub.State{AppID: app.ID, Image: image, TagsJSON: `{"1.0.0":"1.0.0","2.0.0":"2.0.0","2.1.0":"2.1.0"}`, NextSyncAt: fixtureTime.Add(time.Hour)}).Error; err != nil {
			http.Error(w, "fixture DockerHub state", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"config": config, "key": licenses[0].Key, "other_key": licenses[1].Key, "third_key": licenses[2].Key, "time": time.Now().Unix()})
	})
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in struct {
			Floating        *bool  `json:"floating"`
			GraceHours      *int   `json:"grace_hours"`
			Heartbeat       *int   `json:"heartbeat"`
			Capacity        *int   `json:"capacity"`
			ClockSeconds    *int64 `json:"clock_seconds"`
			ExpiresIn       *int   `json:"expires_in"`
			DisabledVersion string `json:"disabled_version"`
			TrialEnabled    *bool  `json:"trial_enabled"`
			TrialExpire     bool   `json:"trial_expire"`
			TrialConvert    bool   `json:"trial_convert"`
			MaintenanceCase string `json:"maintenance_case"`
			Restart         bool   `json:"restart"`
			Mode            string `json:"mode"`
			Status          string `json:"status"`
			User            string `json:"user"`
			Index           int    `json:"index"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mode = in.Mode
		if len(licenses) > 0 {
			idx := in.Index
			if idx < 0 || idx >= len(licenses) {
				idx = 0
			}
			if in.Status != "" {
				database.Model(&model.License{}).Where("id=?", licenses[idx].ID).Update("status", in.Status)
			}
			if in.User != "" {
				database.Model(&model.EndUser{}).Where("id=?", user.ID).Update("status", in.User)
			}

		}
		if in.ClockSeconds != nil {
			timeOffset.Store(*in.ClockSeconds)
		}
		if in.Floating != nil {
			methods := `["KEY"]`
			if *in.Floating {
				methods = `["KEY","FLOATING"]`
			}
			database.Model(&model.License{}).Where("app_id=?", app.ID).Updates(map[string]any{"verify_methods": methods, "max_activations": 1})
		}
		if in.Capacity != nil {
			database.Model(&model.License{}).Where("app_id=?", app.ID).Update("max_activations", *in.Capacity)
		}
		if in.GraceHours != nil {
			database.Model(&model.Application{}).Where("id=?", app.ID).Update("grace_hours", *in.GraceHours)
		}
		if in.Heartbeat != nil {
			database.Model(&model.Application{}).Where("id=?", app.ID).Updates(map[string]any{"heartbeat_interval": *in.Heartbeat, "next_check_in": 1})
		}
		if in.ExpiresIn != nil {
			end := serviceOptions.Now().Add(time.Duration(*in.ExpiresIn) * time.Second)
			database.Model(&model.License{}).Where("id=?", licenses[0].ID).Updates(map[string]any{"expires_at": end, "validity_rule": "fixed_expiry"})
		}
		if in.DisabledVersion != "" {
			now := serviceOptions.Now()
			database.Create(&model.AppVersion{AppID: app.ID, Version: in.DisabledVersion, Disabled: true, PublishedAt: &now})
		}
		if in.TrialEnabled != nil {
			database.Model(&model.Application{}).Where("id=?", app.ID).Updates(map[string]any{"trial_enabled": *in.TrialEnabled, "trial_days": 14})
		}
		var issued model.License
		database.Where("app_id=? AND source='self_trial'", app.ID).First(&issued)
		if in.TrialExpire && issued.ID != 0 {
			end := serviceOptions.Now().Add(-time.Second)
			database.Model(&issued).Update("expires_at", end)
		}
		if in.TrialConvert && issued.ID != 0 {
			days := 30
			_, e := trial.New(database, serviceOptions.Now).Convert(r.Context(), issued.ID, trial.ConvertInput{UserID: user.ID, Days: &days})
			if e != nil {
				http.Error(w, "conversion failed", 500)
				return
			}
		}
		if in.MaintenanceCase != "" {
			bound := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
			limit := bound
			if in.MaintenanceCase == "renew" {
				limit = bound.Add(24 * time.Hour)
			}
			database.Model(&model.License{}).Where("id=?", licenses[0].ID).Update("maintenance_until", limit)
			database.Where("app_id=? AND version IN ?", app.ID, []string{"1.0.0", "2.0.0"}).Delete(&model.AppVersion{})
			before := bound.Add(-time.Second)
			database.Create(&model.AppVersion{AppID: app.ID, Version: "2.0.0", Source: "docker", PublishedAt: &before})
			published := bound
			switch in.MaintenanceCase {
			case "before":
				published = before
			case "after", "renew", "none":
				published = bound.Add(time.Second)
			}
			if in.MaintenanceCase != "unknown" {
				v := model.AppVersion{AppID: app.ID, Version: "1.0.0", Source: "docker", PublishedAt: &published}
				if in.MaintenanceCase == "missing" {
					v.PublishedAt = nil
				}
				database.Create(&v)
			}
			if in.MaintenanceCase == "none" {
				database.Model(&model.AppVersion{}).Where("app_id=? AND version=?", app.ID, "2.0.0").Update("disabled", true)
			}
			if in.MaintenanceCase == "clear" {
				database.Model(&model.License{}).Where("id=?", licenses[0].ID).Update("maintenance_until", nil)
			}
		}
		if in.Restart {
			clients.Close(context.Background())
			clients, e = client.NewService(database, master, log, serviceOptions)
			if e != nil {
				http.Error(w, "test service restart", 500)
				return
			}
			router = gin.New()
			clients.Register(router)
		}
		var current model.License
		var trialCount, trialConverted, trialClaims, trialActive int64
		database.Model(&model.License{}).Where("app_id=? AND source='self_trial'", app.ID).Count(&trialCount)
		database.Model(&model.License{}).Where("app_id=? AND source='self_trial' AND converted_at IS NOT NULL", app.ID).Count(&trialConverted)
		database.Model(&trial.Claim{}).Where("app_id=?", app.ID).Count(&trialClaims)
		database.Model(&model.Activation{}).Where("license_id IN (SELECT id FROM licenses WHERE app_id=? AND source='self_trial') AND kind='floating' AND status='active' AND offline_at IS NULL AND lease_expires_at>?", app.ID, serviceOptions.Now()).Count(&trialActive)
		var leaseCount, sessionCount int64
		var rows []model.Activation
		database.First(&current, licenses[0].ID)
		database.Where("license_id=?", current.ID).Find(&rows)
		database.Model(&model.Activation{}).Where("license_id=? AND kind='floating' AND status='active' AND lease_expires_at>?", current.ID, serviceOptions.Now()).Count(&leaseCount)
		database.Model(&model.ClientSession{}).Where("license_id=?", current.ID).Count(&sessionCount)
		sessionValid := true
		for _, row := range rows {
			if row.InstanceSession != "" {
				raw, err := base64.RawURLEncoding.DecodeString(row.InstanceSession)
				sessionValid = sessionValid && err == nil && len(raw) == 16
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "live_leases": leaseCount, "sessions": sessionCount, "session_valid": sessionValid, "trial_count": trialCount, "trial_converted": trialConverted, "trial_claims": trialClaims, "trial_active": trialActive, "gateway_calls": gatewayCalls.Load()})

	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current := mode
		mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/gateway") {
			router.ServeHTTP(w, r)
			return
		}
		gatewayCalls.Add(1)
		if current == "disconnect" {
			if h, ok := w.(http.Hijacker); ok {
				conn, _, _ := h.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
			return
		}
		if current == "502" {
			w.WriteHeader(502)
			return
		}
		if current == "html" {
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		if current == "" {
			router.ServeHTTP(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var outer wire.Request
		_ = json.Unmarshal(raw, &outer)
		private, e := keys.Private(r.Context(), outer.K, time.Now())
		if e != nil {
			w.WriteHeader(400)
			return
		}
		plain, session, e := wire.Decrypt(private, outer)
		if e != nil {
			w.WriteHeader(400)
			return
		}
		var inner wire.Inner
		_ = json.Unmarshal(plain, &inner)
		if current == "bad-ticket" || current == "no-signature" || current == "no-ticket" || current == "expired-ticket" {
			r.Body = io.NopCloser(bytes.NewReader(raw))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, r)
			var encrypted wire.Response
			_ = json.Unmarshal(rec.Body.Bytes(), &encrypted)
			response, e := session.DecryptResponse(encrypted)
			if e != nil {
				http.Error(w, "fixture response", 500)
				return
			}
			var env map[string]any
			decoder := json.NewDecoder(bytes.NewReader(response))
			decoder.UseNumber()
			_ = decoder.Decode(&env)
			if current != "no-signature" {
				data, _ := env["data"].(map[string]any)
				if current == "bad-ticket" {
					data["ticket"] = "invalid.ticket"
				}
				if current == "no-ticket" {
					delete(data, "ticket")
				}
				mu.Lock()
				a := app
				mu.Unlock()
				pk, _ := box.Decrypt(a.PrivateKeyEncrypted, []byte("application:"+a.AppKey+":ed25519_private_key"))
				if current == "expired-ticket" {
					public, _ := base64.StdEncoding.DecodeString(a.PublicKey)
					g, e := wire.DecodeTicket(data["ticket"].(string), ed25519.PublicKey(public))
					if e != nil {
						http.Error(w, "test grant", 500)
						return
					}
					expired := fixtureTime.Add(-time.Second)
					g.ExpiresAt = &expired
					data["expires_at"] = &expired
					data["ticket"], _ = wire.EncodeTicket(g, ed25519.PrivateKey(pk))
				}
				signed, _ := cryptoutil.CanonicalJSON(map[string]any{"code": env["code"], "data": env["data"], "ts": env["ts"]})
				env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(pk), signed))
			} else {
				env["signature"] = nil
			}
			out, _ := json.Marshal(env)
			ct, _ := session.EncryptResponse(out)
			_ = json.NewEncoder(w).Encode(ct)
			return
		}
		if current == "tamper" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"n":"AAAAAAAAAAAAAAAA","c":"AAAAAAAAAAAAAAAAAAAAAA"}`))
			return
		}
		mu.Lock()
		a := app
		mu.Unlock()
		pk, _ := box.Decrypt(a.PrivateKeyEncrypted, []byte("application:"+a.AppKey+":ed25519_private_key"))
		data := map[string]any{"request_nonce": inner.Nonce}
		stamp := serviceOptions.Now().Unix()
		canonical, _ := cryptoutil.CanonicalJSON(map[string]any{"code": current, "data": data, "ts": stamp})
		sig := ed25519.Sign(ed25519.PrivateKey(pk), canonical)
		env, _ := json.Marshal(map[string]any{"code": current, "message": "test fault", "data": data, "ts": stamp, "nonce": inner.Nonce, "signature": base64.StdEncoding.EncodeToString(sig)})
		encrypted, _ := session.EncryptResponse(env)
		_ = json.NewEncoder(w).Encode(encrypted)
	})
	server := &http.Server{Addr: "0.0.0.0:18091", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
		go func() { _ = server.Shutdown(context.Background()); close(done) }()
	})
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Error(err)
			close(done)
		}
	}()
	select {
	case <-done:
	case <-time.After(25 * time.Minute):
		t.Error("conformance host timed out")
	}
}
