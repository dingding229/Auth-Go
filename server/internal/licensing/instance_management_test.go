package licensing

import (
	"authgo/internal/model"
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"net/url"
	"testing"
	"time"
)

func TestOnlineInstanceCountsAndReleaseDeletesInstance(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.create(t)
	other := f.create(t)
	now := f.clock.now().UTC()
	future := now.Add(time.Minute)
	past := now.Add(-time.Second)
	rows := []model.Activation{
		{Kind: "floating", Status: "active", LeaseExpiresAt: &future},
		{Kind: "floating", Status: "active", LeaseExpiresAt: &now},
		{Kind: "floating", Status: "active", LeaseExpiresAt: &past},
		{Kind: "floating", Status: "active", LeaseExpiresAt: &future, OfflineAt: &past},
		{Kind: "floating", Status: "unbound", LeaseExpiresAt: &future},
		{Kind: "key", Status: "active", LeaseExpiresAt: &future},
	}
	for i := range rows {
		rows[i].LicenseID = l.ID
		rows[i].Value = fmt.Sprint(i)
		rows[i].Token = fmt.Sprintf("instance-%d", i)
		if err := f.db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Resolve request-style PHP session IDs in one query, without changing bindings.
	session := model.ClientSession{ID: rows[0].Value, LicenseID: l.ID, AppID: l.AppID, TokenHash: "test-session", Device: "real-container-fingerprint"}
	if err := f.db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	items, _, err := f.s.List(ctx, Filter{Query: listQuery(t, url.Values{})})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		want := int64(0)
		if item.ID == l.ID {
			want = 1
		}
		if item.OnlineInstances != want {
			t.Fatal(item.ID, item.OnlineInstances)
		}
	}
	detail, err := f.s.Get(ctx, l.ID)
	if err != nil || detail.OnlineInstances != 1 {
		t.Fatal(detail, err)
	}
	activations, _, err := f.s.ListActivations(ctx, listQuery(t, url.Values{}), &l.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range activations {
		if a.ID == rows[0].ID && a.InstanceID != session.Device {
			t.Fatal(a.InstanceID)
		}
	}

	filtered, total, err := f.s.ListActivations(ctx, listQuery(t, url.Values{}), &l.ID, ActivationFilter{Kind: "floating"})
	if err != nil || total != 5 || len(filtered) != 5 {
		t.Fatal(total, err)
	}
	_, _, err = f.s.ListActivations(ctx, listQuery(t, url.Values{}), &l.ID, ActivationFilter{Kind: "invalid"})
	status(t, err, 400)

	released, err := f.s.ReleaseSeat(ctx, rows[0].ID)
	if err != nil || released.LeaseExpiresAt == nil || !released.LeaseExpiresAt.Equal(now) {
		t.Fatal(released, err)
	}
	var after model.Activation
	if err := f.db.First(&after, rows[0].ID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatal("released instance retained", err)
	}
	detail, err = f.s.Get(ctx, l.ID)
	if err != nil || detail.OnlineInstances != 0 {
		t.Fatal(detail, err)
	}
	empty, err := f.s.Get(ctx, other.ID)
	if err != nil || empty.OnlineInstances != 0 {
		t.Fatal(empty, err)
	}
	_, err = f.s.ReleaseSeat(ctx, rows[5].ID)
	status(t, err, 409)
	_, err = f.s.ReleaseSeat(ctx, rows[4].ID)
	status(t, err, 409)
	_, err = f.s.ReleaseSeat(ctx, 999999)
	status(t, err, 404)
}
