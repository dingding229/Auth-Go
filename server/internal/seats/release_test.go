package seats

import (
	"authgo/internal/db"
	"authgo/internal/model"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestReleaseDeletionAndAuditAreAtomic(t *testing.T) {
	d, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if err = db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	app := model.Application{AppKey: "test", Name: "test"}
	if err = d.Create(&app).Error; err != nil {
		t.Fatal(err)
	}
	l := model.License{AppID: app.ID, Key: "license", Status: "active"}
	if err = d.Create(&l).Error; err != nil {
		t.Fatal(err)
	}
	a := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "instance", Token: "generation", Status: "active"}
	if err = d.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if err = d.Exec("CREATE TRIGGER refuse_instance_delete BEFORE DELETE ON activations BEGIN SELECT RAISE(ABORT,'test-only'); END").Error; err != nil {
		t.Fatal(err)
	}
	err = d.Transaction(func(tx *gorm.DB) error { return Release(tx, a, time.Now(), "sdk") })
	if err == nil {
		t.Fatal("expected deletion failure")
	}
	var rows, audits int64
	d.Model(&model.Activation{}).Where("id=?", a.ID).Count(&rows)
	d.Model(&model.AuditLog{}).Where("action='instance.release'").Count(&audits)
	if rows != 1 || audits != 0 {
		t.Fatal("non-atomic release", rows, audits)
	}
	if err = d.Exec("DROP TRIGGER refuse_instance_delete").Error; err != nil {
		t.Fatal(err)
	}
	if err = d.Exec("CREATE TRIGGER refuse_release_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'test-only'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err = d.Transaction(func(tx *gorm.DB) error { return Release(tx, a, time.Now(), "sdk") }); err == nil {
		t.Fatal("audit failure did not block release")
	}
	d.Model(&model.Activation{}).Where("id=?", a.ID).Count(&rows)
	if rows != 1 {
		t.Fatal("audit failure deleted instance")
	}

}
