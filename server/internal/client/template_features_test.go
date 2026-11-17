package client

import (
	"authgo/internal/code"
	"authgo/internal/model"
	featuretemplate "authgo/internal/template"
	"authgo/internal/verify"
	"authgo/sdk/wire"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestTemplateSyncFeaturesReachVerificationAndHeartbeat(t *testing.T) {
	for _, op := range []string{verify.Verify, verify.Heartbeat} {
		t.Run(op, func(t *testing.T) {
			f := newUnlockFixture(t)
			source := model.FeatureTemplate{AppID: f.app.ID, Name: "新功能", Features: model.JSONMap{"export": true}}
			if err := f.db.Create(&source).Error; err != nil {
				t.Fatal(err)
			}
			out, err := featuretemplate.New(f.db).Sync(context.Background(), f.app.ID, source.ID, featuretemplate.SyncInput{Scope: "all"})
			if err != nil || out.Count != 1 {
				t.Fatal(out, err)
			}
			result := f.service.process(context.Background(), f.app, op, "203.0.113.7", f.in, f.clock.now(), policyOptions{})
			if result.Code != code.OK {
				t.Fatal(result.Code)
			}
			features, err := json.Marshal(result.Data["features"])
			if err != nil || string(features) != `{"export":true}` {
				t.Fatal(string(features), err)
			}
			public, err := base64.StdEncoding.DecodeString(f.app.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := wire.DecodeTicket(result.Data["ticket"].(string), public)
			if err != nil || string(grant.Features) != `{"export":true}` {
				t.Fatal("signed ticket did not carry synchronized features", string(grant.Features), err)
			}
		})
	}
}
