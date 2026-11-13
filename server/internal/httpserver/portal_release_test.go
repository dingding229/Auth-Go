package httpserver

import (
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"testing"
)

func TestPortalReleaseIsOwnedAndKeepsGeneration(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	now := f.clock.now()
	a := model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "instance", Status: "active", Token: "contract-proof", LeaseExpiresAt: &now}
	if e := f.db.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	other := model.EndUser{Name: "other", Status: "active"}
	f.db.Create(&other)
	l, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: &other.ID})
	if e != nil {
		t.Fatal(e)
	}
	b := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "other", Status: "active", Token: "other-proof"}
	f.db.Create(&b)
	f.p(t, "POST", fmt.Sprintf("/user/instances/%d/release-seat", b.ID), token, gin.H{}, "NOT_FOUND")
	f.p(t, "POST", fmt.Sprintf("/user/instances/%d/release-seat", a.ID), token, gin.H{}, "OK")
	if err := f.db.First(&model.Activation{}, a.ID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatal("released instance retained", err)
	}
	if err := f.db.First(&model.Activation{}, b.ID).Error; err != nil {
		t.Fatal("another user's instance changed", err)
	}
}
