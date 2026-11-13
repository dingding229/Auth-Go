package keycheck_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	cryptoutil "authgo/internal/crypto"
	"authgo/internal/db"
	"authgo/internal/keycheck"
)

func TestStartupCiphertextFamiliesReadOnly(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	box, _ := cryptoutil.NewCipher(master)
	cases := []struct {
		table, column, extra, aad string
		totp                      bool
	}{
		{"applications", "app_secret_encrypted", "app_key TEXT DEFAULT 'app'", "application:app:app_secret", false},
		{"applications", "private_key_encrypted", "app_key TEXT DEFAULT 'app'", "application:app:ed25519_private_key", false},
		{"applications", "unlock_secret_encrypted", "app_key TEXT DEFAULT 'app'", "application:app:unlock_secret", false},
		{"gateway_keys", "private_encrypted", "id TEXT DEFAULT 'key'", "authgo/gateway/v2/key", false},
		{"admins", "totp_secret", "id INTEGER DEFAULT 1", "admin:1:totp:active", true},
		{"admins", "pending_totp_secret", "id INTEGER DEFAULT 1", "admin:1:totp:pending", true},
		{"payload_keys", "private_key_encrypted", "app_id INTEGER DEFAULT 1, key_id TEXT DEFAULT 'key'", "application:app:payload_key:key", false},
		{"settings", "value", "key TEXT DEFAULT 'system.v1'", "authgo/system/smtp-password/v1", false},
	}
	for _, tc := range cases {
		t.Run(tc.table+"/"+tc.column, func(t *testing.T) {
			d, e := db.Open(t.TempDir(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			pool, _ := d.DB()
			defer pool.Close()
			exec := func(sql string, args ...any) {
				t.Helper()
				if e := d.Exec(sql, args...).Error; e != nil {
					t.Fatal(e)
				}
			}
			exec(fmt.Sprintf("CREATE TABLE %s (%s TEXT, %s)", tc.table, tc.column, tc.extra))
			if tc.table == "payload_keys" {
				exec("CREATE TABLE applications (id INTEGER, app_key TEXT)")
				exec("INSERT INTO applications VALUES (1,'app')")
			}
			encrypted, e := box.Encrypt([]byte("private-value"), []byte(tc.aad))
			if e != nil {
				t.Fatal(e)
			}
			if tc.totp {
				key, e := hkdf.Key(sha256.New, master, nil, "authgo/admin/totp-encryption/v1", 32)
				if e != nil {
					t.Fatal(e)
				}
				block, _ := aes.NewCipher(key)
				gcm, _ := cipher.NewGCM(block)
				nonce := make([]byte, gcm.NonceSize())
				encrypted = "v1:" + base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("TOTPSECRET"), []byte(tc.aad)))
			}
			value := encrypted
			if tc.table == "settings" {
				raw, _ := json.Marshal(map[string]any{"smtp": map[string]any{"password_encrypted": encrypted}})
				value = string(raw)
			}
			exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (?)", tc.table, tc.column), value)
			if e := keycheck.Validate(context.Background(), d, master); e != nil {
				t.Fatal("correct key", e)
			}
			var before int64
			d.Raw("SELECT total_changes()").Scan(&before)
			if e := keycheck.Validate(context.Background(), d, bytes.Repeat([]byte{8}, 32)); !errors.Is(e, keycheck.ErrMismatch) {
				t.Fatal("wrong key accepted", e)
			}
			var after int64
			d.Raw("SELECT total_changes()").Scan(&after)
			if before != after {
				t.Fatal("validation wrote database")
			}
			// A valid first row must not mask a later corrupted ciphertext.
			exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (?)", tc.table, tc.column), "broken")
			if tc.table == "settings" {
				exec("UPDATE settings SET value=?", `{"smtp":{"password_encrypted":"broken"}}`)
			}
			if e := keycheck.Validate(context.Background(), d, master); !errors.Is(e, keycheck.ErrMismatch) {
				t.Fatal("corruption accepted", e)
			}
		})
	}
}
