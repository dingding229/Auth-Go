package catalog

import (
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"context"
	"testing"
)

func TestDeleteApplicationRemovesOnlyOwnPayloadKeys(t *testing.T) {
	f := newFixture(t)
	a := f.app(t, "remove")
	b := f.app(t, "keep")
	box, _ := cryptoutil.NewCipher(f.master)
	s := payloadkey.New(f.db, box)
	ctx := context.Background()
	for _, id := range []uint64{a.ID, b.ID} {
		if _, e := s.Rotate(ctx, id); e != nil {
			t.Fatal(e)
		}
	}
	if e := f.s.DeleteApplication(ctx, a.ID); e != nil {
		t.Fatal(e)
	}
	var n int64
	f.db.Model(&payloadkey.Key{}).Where("app_id=?", a.ID).Count(&n)
	if n != 0 {
		t.Fatal("orphaned keys")
	}
	f.db.Model(&payloadkey.Key{}).Where("app_id=?", b.ID).Count(&n)
	if n != 1 {
		t.Fatal("other app affected")
	}
	l := model.License{AppID: b.ID, Key: "referenced", Features: model.JSONMap{}}
	if e := f.db.Create(&l).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.s.DeleteApplication(ctx, b.ID); e == nil {
		t.Fatal("deleted licensed app")
	}
	f.db.Model(&payloadkey.Key{}).Where("app_id=?", b.ID).Count(&n)
	if n != 1 {
		t.Fatal("rejection removed key")
	}
}
