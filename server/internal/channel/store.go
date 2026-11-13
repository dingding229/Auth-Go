package channel

import (
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/sdk/wire"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"gorm.io/gorm"
	"time"
)

type Key struct {
	ID               string     `gorm:"primaryKey" json:"id"`
	PublicKey        string     `json:"public_key"`
	PrivateEncrypted string     `json:"-"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at"`
}

func (Key) TableName() string { return "gateway_keys" }

type Store struct {
	DB     *gorm.DB
	Cipher *cryptoutil.Cipher
}

func New(db *gorm.DB, master []byte) (*Store, error) {
	box, e := cryptoutil.NewCipher(master)
	if e != nil {
		return nil, e
	}
	s := &Store{db, box}
	_, e = s.Current(context.Background())
	if e != nil {
		return nil, e
	}
	var ids []uint64
	if e = s.DB.Model(&model.Application{}).Where("unlock_secret_encrypted='' OR license_salt='' OR unlock_secret_encrypted IS NULL OR license_salt IS NULL").Pluck("id", &ids).Error; e != nil {
		return nil, e
	}
	for _, id := range ids {
		if _, e = s.EnsureApplication(context.Background(), id); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) Current(ctx context.Context) (Key, error) {
	var k Key
	e := s.DB.WithContext(ctx).Where("expires_at IS NULL").Order("created_at DESC").First(&k).Error
	if errors.Is(e, gorm.ErrRecordNotFound) {
		return s.Rotate(ctx, 7*24*time.Hour)
	}
	return k, e
}
func (s *Store) Rotate(ctx context.Context, overlap time.Duration) (Key, error) {
	var k Key
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return k, e
	}
	k = Key{ID: wire.KeyID(priv.PublicKey().Bytes()), PublicKey: wire.B64.EncodeToString(priv.PublicKey().Bytes()), CreatedAt: time.Now().UTC()}
	k.PrivateEncrypted, e = s.Cipher.Encrypt(priv.Bytes(), []byte("authgo/gateway/v2/"+k.ID))
	if e != nil {
		return k, e
	}
	e = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.Where("expires_at IS NOT NULL").Delete(&Key{}).Error; e != nil {
			return e
		}
		if e := tx.Model(&Key{}).Where("expires_at IS NULL").Update("expires_at", time.Now().UTC().Add(overlap)).Error; e != nil {
			return e
		}
		return tx.Create(&k).Error
	})
	return k, e
}
func (s *Store) Private(ctx context.Context, id string, now time.Time) (*ecdh.PrivateKey, error) {
	if len(id) != 16 {
		return nil, wire.ErrInvalid
	}
	var k Key
	if e := s.DB.WithContext(ctx).Where("id=? AND (expires_at IS NULL OR expires_at>?)", id, now.UTC()).First(&k).Error; e != nil {
		return nil, wire.ErrInvalid
	}
	raw, e := s.Cipher.Decrypt(k.PrivateEncrypted, []byte("authgo/gateway/v2/"+id))
	if e != nil {
		return nil, e
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// EnsureApplication is safe against concurrent first use: losers read the winner.
func (s *Store) EnsureApplication(ctx context.Context, id uint64) (model.Application, error) {
	var a model.Application
	e := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.First(&a, id).Error; e != nil {
			return e
		}
		updates := map[string]any{}
		if a.UnlockSecretEncrypted == "" {
			raw := make([]byte, 32)
			if _, e := rand.Read(raw); e != nil {
				return e
			}
			enc, e := s.Cipher.Encrypt(raw, []byte("application:"+a.AppKey+":unlock_secret"))
			if e != nil {
				return e
			}
			updates["unlock_secret_encrypted"] = enc
		}
		if a.LicenseSalt == "" {
			salt, e := cryptoutil.RandomString(32)
			if e != nil {
				return e
			}
			updates["license_salt"] = salt
		}
		if len(updates) > 0 {
			if e := tx.Model(&a).Updates(updates).Error; e != nil {
				return e
			}
			return tx.First(&a, id).Error
		}
		return nil
	})
	return a, e
}
