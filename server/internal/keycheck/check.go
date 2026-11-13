// Package keycheck verifies persisted ciphertext before startup can migrate or back up a database.
package keycheck

import (
	"authgo/internal/auth"
	cryptoutil "authgo/internal/crypto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
)

var ErrMismatch = errors.New("无法使用当前主密钥验证已有密文，已拒绝启动；请恢复原 AUTHGO_MASTER_KEY/master.key 或检查数据库完整性")

// Validate is read-only and supports pre-migration schemas. Empty/new databases
// have no ciphertext to verify. Every nonempty known ciphertext is checked, not
// just the first row (which could hide a partial key mismatch/corruption).
func Validate(ctx context.Context, database *gorm.DB, master []byte) error {
	database = database.WithContext(ctx)
	// SQLite's HasColumn can match suffixes (totp_secret/pending_totp_secret).
	// Use exact schema names, and fail closed if introspection itself fails.
	tables, err := database.Migrator().GetTables()
	if err != nil {
		return ErrMismatch
	}
	schema := map[string]map[string]bool{}
	for _, table := range tables {
		schema[table] = nil
	}
	hasColumn := func(table, column string) (bool, error) {
		columns, exists := schema[table]
		if !exists {
			return false, nil
		}
		if columns == nil {
			types, err := database.Migrator().ColumnTypes(table)
			if err != nil {
				return false, err
			}
			columns = map[string]bool{}
			for _, typ := range types {
				columns[typ.Name()] = true
			}
			schema[table] = columns
		}
		return columns[column], nil
	}
	box, err := cryptoutil.NewCipher(master)
	if err != nil {
		return ErrMismatch
	}
	identity, err := auth.NewCrypto(master, nil)
	if err != nil {
		return ErrMismatch
	}
	type rule struct {
		table, column, aad string
		totp               bool
	}
	rules := []rule{
		{"applications", "app_secret_encrypted", "'application:' || app_key || ':app_secret'", false},
		{"applications", "private_key_encrypted", "'application:' || app_key || ':ed25519_private_key'", false},
		{"applications", "unlock_secret_encrypted", "'application:' || app_key || ':unlock_secret'", false},
		{"gateway_keys", "private_encrypted", "'authgo/gateway/v2/' || id", false},
		{"admins", "totp_secret", "'admin:' || id || ':totp:active'", true},
		{"admins", "pending_totp_secret", "'admin:' || id || ':totp:pending'", true},
	}
	for _, r := range rules {
		exists, schemaErr := hasColumn(r.table, r.column)
		if schemaErr != nil {
			return ErrMismatch
		}
		if !exists {
			continue
		}
		// Identifiers/expressions are constants above, never user input.
		query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND %s<>''", r.column, r.aad, r.table, r.column, r.column)
		rows, e := database.WithContext(ctx).Raw(query).Rows()
		if e != nil {
			return ErrMismatch
		}
		valid := true
		for rows.Next() {
			var value, aad string
			if e = rows.Scan(&value, &aad); e != nil {
				valid = false
				break
			}
			if r.totp {
				e = identity.CheckEncryptedSecret(value, aad)
			} else {
				var plain []byte
				plain, e = box.Decrypt(value, []byte(aad))
				clear(plain)
			}
			if e != nil {
				valid = false
				break
			}
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if !valid || readErr != nil || closeErr != nil {
			return ErrMismatch
		}
	}
	payload, schemaErr := hasColumn("payload_keys", "private_key_encrypted")
	if schemaErr != nil {
		return ErrMismatch
	}
	if payload {
		rows, e := database.WithContext(ctx).Raw("SELECT p.private_key_encrypted, 'application:' || a.app_key || ':payload_key:' || p.key_id FROM payload_keys p LEFT JOIN applications a ON a.id=p.app_id WHERE p.private_key_encrypted IS NOT NULL AND p.private_key_encrypted<>''").Rows()
		if e != nil {
			return ErrMismatch
		}
		valid := true
		for rows.Next() {
			var value, aad string
			if e = rows.Scan(&value, &aad); e != nil {
				valid = false
				break
			}
			plain, e := box.Decrypt(value, []byte(aad))
			clear(plain)
			if e != nil {
				valid = false
				break
			}
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if !valid || readErr != nil || closeErr != nil {
			return ErrMismatch
		}
	}
	if _, exists := schema["settings"]; exists {
		var raw string
		if e := database.WithContext(ctx).Table("settings").Select("value").Where("key=?", "system.v1").Scan(&raw).Error; e != nil {
			return ErrMismatch
		}
		if raw != "" {
			var settings struct {
				SMTP struct {
					Password string `json:"password_encrypted"`
				} `json:"smtp"`
			}
			if json.Unmarshal([]byte(raw), &settings) != nil {
				return ErrMismatch
			}
			if value := settings.SMTP.Password; value != "" {
				plain, e := box.Decrypt(value, []byte("authgo/system/smtp-password/v1"))
				clear(plain)
				if e != nil {
					return ErrMismatch
				}
			}
		}
	}
	return nil
}
