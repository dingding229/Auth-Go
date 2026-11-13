// Package payloadkey owns software packaging keys and the encrypted payload format.
package payloadkey

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"gorm.io/gorm"
	"time"
)

type Key struct {
	ID                  uint64    `gorm:"primaryKey" json:"-"`
	AppID               uint64    `json:"-"`
	KeyID               string    `json:"key_id"`
	PublicKey           string    `json:"public_key"`
	PrivateKeyEncrypted string    `json:"-"`
	IsCurrent           bool      `json:"is_current"`
	CreatedAt           time.Time `json:"created_at"`
}

func (Key) TableName() string { return "payload_keys" }

// Info deliberately cannot carry private key material, even in internal API envelopes.
type Info struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	IsCurrent bool      `json:"is_current"`
	CreatedAt time.Time `json:"created_at"`
}

func public(k Key) Info { return Info{k.KeyID, k.PublicKey, k.IsCurrent, k.CreatedAt} }

type Service struct {
	db     *gorm.DB
	cipher *cryptoutil.Cipher
}

func New(db *gorm.DB, box *cryptoutil.Cipher) *Service { return &Service{db, box} }
func aad(app, key string) []byte                       { return []byte("application:" + app + ":payload_key:" + key) }
func findApp(tx *gorm.DB, id uint64) (model.Application, error) {
	var a model.Application
	err := tx.First(&a, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = apperror.NotFound()
	}
	return a, err
}
func (s *Service) List(ctx context.Context, id uint64) ([]Info, error) {
	out := []Info{}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, e := findApp(tx, id); e != nil {
			return e
		}
		var keys []Key
		if e := tx.Where("app_id=?", id).Order("is_current DESC, id DESC").Find(&keys).Error; e != nil {
			return e
		}
		for _, k := range keys {
			out = append(out, public(k))
		}
		return nil
	})
	return out, err
}
func (s *Service) Rotate(ctx context.Context, id uint64) (Info, error) {
	var out Info
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, e := findApp(tx, id)
		if e != nil {
			return e
		}
		private, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		raw := private.Bytes()
		defer clear(raw)
		name := make([]byte, 16)
		if _, e = rand.Read(name); e != nil {
			return e
		}
		k := Key{AppID: id, KeyID: "pk_" + hex.EncodeToString(name), PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), IsCurrent: true, CreatedAt: time.Now().UTC()}
		k.PrivateKeyEncrypted, e = s.cipher.Encrypt(raw, aad(a.AppKey, k.KeyID))
		if e != nil {
			return e
		}
		if e = tx.Model(&Key{}).Where("app_id=? AND is_current=1", id).Update("is_current", false).Error; e != nil {
			return e
		}
		if e = tx.Create(&k).Error; e != nil {
			return e
		}
		out = public(k)
		return nil
	})
	return out, err
}

// Open is called only inside the already-authorized gateway transaction.
// Never use payload.Config as a connection target or reconstruct it from current settings.
func (s *Service) Open(tx *gorm.DB, a model.Application, p Payload) ([]byte, error) {
	if p.AppKey != a.AppKey {
		return nil, ErrInvalid
	}
	if _, e := p.aad(); e != nil {
		return nil, ErrInvalid
	}
	var key Key
	if e := tx.Where("app_id=? AND key_id=?", a.ID, p.KeyID).First(&key).Error; e != nil {
		return nil, ErrInvalid
	}
	raw, e := s.cipher.Decrypt(key.PrivateKeyEncrypted, aad(a.AppKey, key.KeyID))
	if e != nil {
		return nil, ErrInvalid
	}
	defer clear(raw)
	return OpenEnvelope(p, raw)
}
