package enduser

import (
	"authgo/internal/db"
	"authgo/internal/model"
	"context"
	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }
func TestUserCRUDAndCredentialVersion(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	s := Service{DB: d}
	ctx := context.Background()
	u, e := s.Create(ctx, Input{Name: ptr(" 张三 "), Email: ptr(" A@EXAMPLE.COM "), PortalPassword: ptr("password123")})
	if e != nil || u.Name != "张三" || u.Email != "a@example.com" || !u.HasPortalPassword {
		t.Fatal(u, e)
	}
	if _, e = s.Create(ctx, Input{Name: ptr("other"), Email: ptr("a@example.com")}); e == nil {
		t.Fatal("duplicate email")
	}
	for _, mail := range []string{"bad", "Name <a@example.com>"} {
		if _, e = s.Create(ctx, Input{Name: ptr("x"), Email: &mail}); e == nil {
			t.Fatal("invalid email")
		}
	}
	var stored model.EndUser
	d.First(&stored, u.ID)
	if bcrypt.CompareHashAndPassword([]byte(stored.PortalPasswordHash), []byte("password123")) != nil {
		t.Fatal("plaintext password")
	}
	for _, in := range []Input{{Email: ptr("b@example.com")}, {Status: ptr("disabled")}, {Status: ptr("active")}, {PortalPassword: ptr("newpassword")}} {
		before := stored.AuthVersion
		if _, e = s.Update(ctx, u.ID, in); e != nil {
			t.Fatal(e)
		}
		d.First(&stored, u.ID)
		if stored.AuthVersion != before+1 {
			t.Fatal("credential version not bumped")
		}
	}
	a := model.Application{Name: "software", AppKey: "test", PublicKey: "p", PrivateKeyEncrypted: "c", AppSecretEncrypted: "c"}
	d.Create(&a)
	d.Create(&model.License{AppID: a.ID, UserID: &u.ID, Key: "KEY"})
	if e = s.Delete(ctx, u.ID); e == nil {
		t.Fatal("deleted owner")
	}
	empty, e := s.Create(ctx, Input{Name: ptr("无授权")})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Delete(ctx, empty.ID); e != nil {
		t.Fatal(e)
	}
}
