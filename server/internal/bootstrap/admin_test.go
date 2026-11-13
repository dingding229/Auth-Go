package bootstrap

import (
	"testing"
	"time"

	"authgo/internal/db"
	"authgo/internal/model"

	"golang.org/x/crypto/bcrypt"
)

func TestEnsureAdmin(t *testing.T) {
	for _, password := range []string{"provided-password", ""} {
		name := "provided"
		if password == "" {
			name = "generated"
		}
		t.Run(name, func(t *testing.T) {
			database, err := db.Open(t.TempDir(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			pool, _ := database.DB()
			defer pool.Close()
			if err := db.Migrate(database); err != nil {
				t.Fatal(err)
			}
			result, err := EnsureAdmin(database, "owner", password)
			if err != nil {
				t.Fatal(err)
			}
			if password == "" {
				if result.Created {
					t.Fatal("无密码不得自动创建管理员")
				}
				var count int64
				database.Model(&model.Admin{}).Count(&count)
				if count != 0 {
					t.Fatal("无密码创建了管理员")
				}
				return
			}
			if !result.Created {
				t.Fatal("admin not created")
			}
			var admin model.Admin
			if err := database.First(&admin).Error; err != nil {
				t.Fatal(err)
			}
			if admin.Username != "owner" || admin.PasswordHash == password {
				t.Fatal("invalid admin")
			}
			if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
				t.Fatal(err)
			}
			second, err := EnsureAdmin(database, "replacement", "new-password")
			if err != nil {
				t.Fatal(err)
			}
			if second.Created {
				t.Fatal("reinitialized existing admin")
			}
			var persisted model.Admin
			if err := database.First(&persisted).Error; err != nil {
				t.Fatal(err)
			}
			if persisted.PasswordHash != admin.PasswordHash || persisted.Username != admin.Username {
				t.Fatal("overwrote credentials")
			}
			var count int64
			database.Model(&model.Admin{}).Count(&count)
			if count != 1 {
				t.Fatalf("admin count %d", count)
			}
		})
	}
}
