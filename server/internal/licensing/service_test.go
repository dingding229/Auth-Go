package licensing

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"authgo/internal/apperror"
	"authgo/internal/db"
	"authgo/internal/enduser"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"authgo/internal/response"

	"gorm.io/gorm"
)

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

type fixture struct {
	s     *Service
	db    *gorm.DB
	clock *testClock
	app   model.Application
	user  model.EndUser
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	app := model.Application{Name: "应用", AppKey: "test-key", AppSecretEncrypted: "cipher", PrivateKeyEncrypted: "cipher", PublicKey: "public"}
	if err := database.Create(&app).Error; err != nil {
		t.Fatal(err)
	}
	clock := &testClock{at: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)}
	user := model.EndUser{Name: "测试用户", Email: "contact@example.com", Status: "active"}
	if e := database.Create(&user).Error; e != nil {
		t.Fatal(e)
	}
	return &fixture{NewServiceWithClock(database, clock.now), database, clock, app, user}
}
func ptr[T any](v T) *T { return &v }
func status(t *testing.T, err error, want int) {
	t.Helper()
	var safe *apperror.Error
	if !errors.As(err, &safe) || safe.Status != want {
		t.Fatalf("error %v want %d", err, want)
	}
}
func (f *fixture) create(t *testing.T) LicenseInfo {
	t.Helper()
	l, err := f.s.Create(context.Background(), CreateInput{UserID: &f.user.ID, AppID: f.app.ID, ValidityRule: ptr("after_activation"), DurationDays: ptr(30), MaxActivations: ptr(3), VerifyMethods: ptr([]string{"KEY", "FLOATING"}), Features: json.RawMessage(`{"quota":18446744073709551615}`)})
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func listQuery(t *testing.T, values url.Values) response.ListQuery {
	t.Helper()
	q, err := response.ParseList(values, "id", "key", "created_at", "status")
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestInvalidCreationPolicies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, in := range []CreateInput{
		{AppID: 999}, {Type: ptr("USER")}, {VerifyMethods: ptr([]string{"DEVICE"})}, {VerifyMethods: ptr([]string{"KEY", "USER"})}, {VerifyMethods: ptr([]string{"KEY", "KEY"})},
		{MaxActivations: ptr(0)}, {MatchMode: ptr("bad")},
		{Features: json.RawMessage(`null`)}, {Metadata: json.RawMessage(`{"a":1,"a":2}`)},
		{ValidityRule: ptr("fixed_days"), DurationDays: ptr(0)}, {ExpiresAt: ptr(f.clock.now().Add(-time.Hour))}, {PortalPassword: ptr("short")}, {Prefix: "VIP"},
	} {
		if in.AppID == 0 {
			in.AppID = f.app.ID
		}
		_, err := f.s.Create(ctx, in)
		if err == nil {
			t.Fatalf("invalid input accepted %+v", in)
		}
	}
}
func TestTransitionMatrix(t *testing.T) {
	allowed := map[string]map[string]string{"unused": {"renew": "unused", "suspend": "suspended", "revoke": "revoked"}, "active": {"renew": "active", "expire": "expired", "suspend": "suspended", "revoke": "revoked"}, "expired": {"renew": "active", "suspend": "suspended", "revoke": "revoked"}, "suspended": {"renew": "suspended", "resume": "active", "revoke": "revoked"}}
	for _, from := range []string{"unused", "active", "expired", "suspended", "revoked", "bad"} {
		for _, action := range []string{"renew", "expire", "suspend", "resume", "revoke", "activate", "bad"} {
			got, err := Transition(from, action)
			want, ok := allowed[from][action]
			if ok {
				if err != nil || got != want {
					t.Fatal(from, action, got, err)
				}
			} else if err == nil {
				t.Fatal("illegal transition", from, action)
			}
		}
	}
}
func TestStateRenewalAndTerminalRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.create(t)
	extended, err := f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(10)})
	if err != nil || extended.DurationDays != 40 || extended.Status != "unused" {
		t.Fatal("unused relative renewal", err)
	}
	expired := f.clock.now().Add(-time.Hour)
	if err := f.db.Model(&model.License{}).Where("id = ?", l.ID).Updates(map[string]any{"status": "expired", "expires_at": expired, "starts_at": expired.Add(-24 * time.Hour), "validity_rule": "fixed_expiry", "duration_days": 0}).Error; err != nil {
		t.Fatal(err)
	}
	renewed, err := f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(5)})
	if err != nil || renewed.Status != "active" || !renewed.ExpiresAt.Equal(f.clock.now().AddDate(0, 0, 5)) {
		t.Fatal("expired renewal", err)
	}
	_, err = f.s.Renew(ctx, l.ID, RenewInput{ExpiresAt: ptr(f.clock.now().Add(time.Hour))})
	status(t, err, 400)
	_, err = f.s.ChangeState(ctx, l.ID, "resume")
	status(t, err, 409)
	if _, err := f.s.ChangeState(ctx, l.ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	f.clock.add(6 * 24 * time.Hour)
	_, err = f.s.ChangeState(ctx, l.ID, "resume")
	status(t, err, 409)
	renewed, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(2)})
	if err != nil || renewed.Status != "suspended" {
		t.Fatal("paused renewal bypassed pause", err)
	}
	if _, err := f.s.ChangeState(ctx, l.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	activation := model.Activation{LicenseID: l.ID, Kind: "key", Value: strings.Repeat("a", 64), Token: "old-live-token"}
	if err := f.db.Create(&activation).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ChangeState(ctx, l.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	var row model.Activation
	f.db.First(&row, activation.ID)
	if row.Status != "revoked" || row.Token == activation.Token || row.OfflineAt == nil {
		t.Fatal("revocation left live binding")
	}
	for _, action := range []string{"resume", "suspend", "revoke"} {
		_, err := f.s.ChangeState(ctx, l.ID, action)
		status(t, err, 409)
	}
	_, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(1)})
	status(t, err, 409)
	status(t, f.s.SetPortalPassword(ctx, l.ID, "new-password"), 409)
}
func TestBatchTenThousandAndRollback(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	result, err := f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{UserID: &f.user.ID, AppID: f.app.ID, Prefix: "BATCH"}, Count: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 10000 || !batchIDValid(result.BatchID) {
		t.Fatal("batch metadata")
	}
	var rows []model.License
	if err := f.db.Where("batch_id = ?", result.BatchID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range rows {
		if seen[l.Key] || licensekey.Validate(l.Key) != nil {
			t.Fatal("duplicate/invalid code")
		}
		seen[l.Key] = true
	}
	if len(seen) != 10000 {
		t.Fatal("partial batch")
	}
	_, err = f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{UserID: &f.user.ID, AppID: f.app.ID}, Count: 10001})
	status(t, err, 400)
	before := len(rows)
	calls := 0
	f.s.generate = func(prefix string) (string, error) {
		calls++
		if calls == 201 {
			return rows[0].Key, nil
		}
		return licensekey.Generate(prefix)
	}
	_, err = f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{UserID: &f.user.ID, AppID: f.app.ID}, Count: 401})
	status(t, err, 409)
	var count int64
	f.db.Model(&model.License{}).Count(&count)
	if count != int64(before) {
		t.Fatal("failed batch was partially committed")
	}
}
func TestActivationManagement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.create(t)
	a := model.Activation{LicenseID: l.ID, Kind: "floating", Value: strings.Repeat("b", 64), Token: "live-token"}
	f.db.Create(&a)
	offline, err := f.s.ManageActivation(ctx, a.ID, false)
	if err != nil || offline.Status != "active" || offline.OfflineAt == nil {
		t.Fatal(err)
	}
	detail, err := f.s.Get(ctx, l.ID)
	if err != nil || len(detail.Activations) != 1 {
		t.Fatal("activation detail")
	}
	raw, _ := json.Marshal(detail)
	if bytes.Contains(raw, []byte("live-token")) || bytes.Contains(raw, []byte("private-challenge")) {
		t.Fatal("token leaked")
	}
	unbound, err := f.s.ManageActivation(ctx, a.ID, true)
	if err != nil || unbound.Status != "unbound" {
		t.Fatal("unbind", err)
	}
	detail, _ = f.s.Get(ctx, l.ID)
}
func TestCSVAtomicReportsAndRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l, err := f.s.Create(ctx, CreateInput{UserID: &f.user.ID, AppID: f.app.ID, Note: ptr("=HYPERLINK(\"x\")"), Metadata: json.RawMessage(`{"quota":18446744073709551615}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.s.Export(ctx, Filter{Query: listQuery(t, url.Values{})})
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	noteIndex := 0
	for i, h := range records[0] {
		if h == "note" {
			noteIndex = i
		}
		if strings.Contains(h, "password") {
			t.Fatal("password column exported")
		}
	}
	if !strings.HasPrefix(records[1][noteIndex], "'=") {
		t.Fatal("spreadsheet formula not escaped")
	}
	// Use a fresh code to import the exported policy; original existing code reports a row error.
	duplicateReport, err := f.s.Import(ctx, raw)
	if err != nil || duplicateReport.Failed != 1 || duplicateReport.Imported != 0 {
		t.Fatal("existing key report", err)
	}
	newKey, _ := licensekey.Generate("CSV")
	records[1][0] = newKey
	var b bytes.Buffer
	writer := csv.NewWriter(&b)
	writer.WriteAll(records)
	report, err := f.s.Import(ctx, b.Bytes())
	if err != nil || report.Imported != 1 || report.Failed != 0 {
		t.Fatalf("import %+v %v", report, err)
	}
	var stored model.License
	f.db.Where("key = ?", newKey).First(&stored)
	if stored.Note != l.Note || stored.Metadata["quota"].(json.Number).String() != "18446744073709551615" {
		t.Fatal("CSV roundtrip modified data")
	}
	another, _ := licensekey.Generate("CSV")
	records[1][0] = another
	bad := append([]string{}, records[1]...)
	bad[0] = "INVALID"
	records = append(records, bad)
	b.Reset()
	writer = csv.NewWriter(&b)
	writer.WriteAll(records)
	report, err = f.s.Import(ctx, b.Bytes())
	if err != nil || report.Failed != 1 || report.Valid != 1 || report.Imported != 0 || report.Errors[0].Row != 3 {
		t.Fatal("row report/atomic validation", report, err)
	}
	var count int64
	f.db.Model(&model.License{}).Where("key = ?", another).Count(&count)
	if count != 0 {
		t.Fatal("valid row was committed from failed file")
	}
}

func TestCSVProtectionAndFailureInputs(t *testing.T) {
	for _, value := range []string{"=SUM(1,2)", "+cmd", "-cmd", "@cmd", "\t=cmd", "\r=cmd", "'=literal", "''literal", "普通文字", ""} {
		if got := csvUnprotect(csvProtect(value)); got != value {
			t.Fatalf("CSV text roundtrip %q -> %q", value, got)
		}
	}
	f := newFixture(t)
	ctx := context.Background()
	for _, raw := range []string{"", "key\n", "key,app_id,portal_password\n", "key,app_id,key\n", string([]byte{0xff})} {
		if _, err := f.s.Import(ctx, []byte(raw)); err == nil {
			t.Fatalf("invalid CSV accepted: %q", raw)
		}
	}
	code, _ := licensekey.Generate("CSV")
	raw := "key,app_id,note\n" + code + ",1,\"unterminated\n"
	report, err := f.s.Import(ctx, []byte(raw))
	if err != nil || report.Failed != 1 || report.Imported != 0 {
		t.Fatal("CSV parse-error report", report, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{UserID: &f.user.ID, AppID: f.app.ID}, Count: 1}); err == nil {
		t.Fatal("canceled batch succeeded")
	}
}
func TestConcurrentStateChangesAndAbsoluteRenewal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l, err := f.s.Create(ctx, CreateInput{UserID: &f.user.ID, AppID: f.app.ID, ValidityRule: ptr("fixed_expiry"), ExpiresAt: ptr(f.clock.now().Add(24 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() { _, err := f.s.ChangeState(ctx, l.ID, "suspend"); results <- err })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			status(t, err, 409)
		}
	}
	if success != 1 {
		t.Fatal("concurrent state transition bypass")
	}
	renewed, err := f.s.Renew(ctx, l.ID, RenewInput{ExpiresAt: ptr(f.clock.now().AddDate(0, 0, 10))})
	if err != nil || renewed.Status != "suspended" {
		t.Fatal(err)
	}
	_, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(1), ExpiresAt: ptr(f.clock.now())})
	status(t, err, 400)
}

func TestRenewCannotOverflowTimestamp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	far := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	l, err := f.s.Create(ctx, CreateInput{UserID: &f.user.ID, AppID: f.app.ID, ExpiresAt: &far})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Renew(ctx, l.ID, RenewInput{Days: ptr(2)})
	status(t, err, 400)
}

func TestUsersCreateAssignBatchCSVAndSearch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	u, e := (enduser.Service{DB: f.db}).Create(ctx, enduser.Input{Name: ptr("张三"), Email: ptr("CONTACT2@EXAMPLE.COM")})
	if e != nil {
		t.Fatal(e)
	}
	input := CreateInput{UserID: &u.ID, AppID: f.app.ID}
	created, e := f.s.Create(ctx, input)
	if e != nil || created.UserName != "张三" || created.UserEmail != "contact2@example.com" {
		t.Fatal(created, e)
	}
	for _, email := range []string{"bad", "Name <test@example.com>", "a@example.com\nb@example.com"} {
		_, e := (enduser.Service{DB: f.db}).Create(ctx, enduser.Input{Name: ptr("test"), Email: &email})
		if e == nil {
			t.Fatalf("invalid email accepted: %q", email)
		}
	}
	updated, e := (enduser.Service{DB: f.db}).Update(ctx, u.ID, enduser.Input{Name: ptr("李四"), Email: ptr("NEW@EXAMPLE.COM")})
	if e != nil || updated.Name != "李四" || updated.Email != "new@example.com" {
		t.Fatal(updated, e)
	}
	for _, term := range []string{"李四", "new@example.com"} {
		_, n, e := f.s.List(ctx, Filter{Query: listQuery(t, url.Values{"q": {term}})})
		if e != nil || n != 1 {
			t.Fatal(term, n, e)
		}
	}
	batch, e := f.s.Batch(ctx, BatchInput{CreateInput: input, Count: 3})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.s.Export(ctx, Filter{Query: listQuery(t, url.Values{}), BatchID: batch.BatchID})
	if e != nil {
		t.Fatal(e)
	}
	records, e := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if e != nil || len(records) != 4 {
		t.Fatal(e, len(records))
	}
	positions := map[string]int{}
	for i, name := range records[0] {
		positions[name] = i
	}
	if records[1][positions["user_name"]] != "李四" || records[1][positions["user_email"]] != "new@example.com" {
		t.Fatal(records[1])
	}
	// Import against another application, changing keys to keep the batch unique.
	other := model.Application{Name: "导入应用", AppKey: "contacts-other", AppSecretEncrypted: "cipher", PrivateKeyEncrypted: "cipher", PublicKey: "public"}
	f.db.Create(&other)
	for i := 1; i < len(records); i++ {
		records[i][positions["app_id"]] = idString(other.ID)
		records[i][positions["key"]], _ = licensekey.Generate("BULK")
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	writer.WriteAll(records)
	imported, e := f.s.Import(ctx, buffer.Bytes())
	if e != nil || imported.Imported != 3 {
		t.Fatal(imported, e)
	}
	values, n, e := f.s.List(ctx, Filter{Query: listQuery(t, url.Values{}), AppID: &other.ID})
	if e != nil || n != 3 || values[0].UserEmail != "new@example.com" {
		t.Fatal(values, n, e)
	}
	if _, e := f.s.Assign(ctx, created.ID, AssignmentInput{UserID: nil}); e != nil {
		t.Fatal(e)
	}
}

func TestInventoryAssignmentAndCSVAtomicUsers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, e := f.s.Create(ctx, CreateInput{AppID: f.app.ID}); e == nil {
		t.Fatal("single without user")
	}
	if _, e := f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{AppID: f.app.ID}, Count: 1}); e == nil {
		t.Fatal("single through batch without user")
	}
	batch, e := f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{AppID: f.app.ID}, Count: 2})
	if e != nil {
		t.Fatal(e)
	}
	items, _, e := f.s.List(ctx, Filter{Query: listQuery(t, url.Values{}), BatchID: batch.BatchID})
	if e != nil || items[0].UserID != nil {
		t.Fatal(items, e)
	}
	for _, userID := range []*uint64{&f.user.ID, nil, &f.user.ID} {
		v, e := f.s.Assign(ctx, items[0].ID, AssignmentInput{UserID: userID})
		if e != nil {
			t.Fatal(e)
		}
		if (v.UserID == nil) != (userID == nil) {
			t.Fatal(v)
		}
	}
	other := model.EndUser{Name: "第二用户"}
	f.db.Create(&other)
	v, e := f.s.Assign(ctx, items[0].ID, AssignmentInput{UserID: &other.ID})
	if e != nil || v.UserName != "第二用户" {
		t.Fatal(v, e)
	}
	key1, _ := licensekey.Generate("CSV")
	key2, _ := licensekey.Generate("CSV")
	raw := []byte("key,app_id,user_name,user_email\n" + key1 + "," + idString(f.app.ID) + ",新用户,new@example.com\n" + key2 + "," + idString(f.app.ID) + ",错误用户,bad-email\n")
	report, e := f.s.Import(ctx, raw)
	if e != nil || report.Failed != 1 {
		t.Fatal(report, e)
	}
	var n int64
	f.db.Model(&model.EndUser{}).Where("email=?", "new@example.com").Count(&n)
	if n != 0 {
		t.Fatal("user committed despite failed CSV")
	}
	raw = bytes.Replace(raw, []byte("bad-email"), []byte("NEW@EXAMPLE.COM"), 1)
	report, e = f.s.Import(ctx, raw)
	if e != nil || report.Imported != 2 {
		t.Fatal(report, e)
	}
	f.db.Model(&model.EndUser{}).Where("email=?", "new@example.com").Count(&n)
	if n != 1 {
		t.Fatal("CSV users not merged")
	}
}

func TestNewIssuanceDefaultsFloating(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	one, e := f.s.Create(ctx, CreateInput{AppID: f.app.ID, UserID: &f.user.ID})
	if e != nil || len(one.VerifyMethods) != 2 || one.VerifyMethods[1] != "FLOATING" || one.MaxActivations != 1 {
		t.Fatal(one, e)
	}
	key, e := f.s.Create(ctx, CreateInput{AppID: f.app.ID, UserID: &f.user.ID, VerifyMethods: ptr([]string{"KEY"})})
	if e != nil || len(key.VerifyMethods) != 1 {
		t.Fatal(key, e)
	}
	b, e := f.s.Batch(ctx, BatchInput{CreateInput: CreateInput{AppID: f.app.ID}, Count: 2})
	if e != nil {
		t.Fatal(e)
	}
	var rows []model.License
	f.db.Where("batch_id=?", b.BatchID).Find(&rows)
	for _, l := range rows {
		if len(l.VerifyMethods) != 2 || l.MaxActivations != 1 {
			t.Fatal(l)
		}
	}
}
