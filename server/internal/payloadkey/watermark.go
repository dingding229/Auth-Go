package payloadkey

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"gorm.io/gorm"
	"regexp"
	"time"
)

var watermarkPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WatermarkTag uses RFC5869 Extract+Expand with an empty salt. The public key
// is the raw 32-byte X25519 key, not its base64/hex representation.
func WatermarkTag(public []byte) (string, error) {
	if len(public) != 32 {
		return "", ErrInvalid
	}
	tag, err := hkdf.Key(sha256.New, public, nil, "authgo/watermark/tag/v1", 16)
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(tag)
	return hex.EncodeToString(tag), nil
}

// LicenseWatermark never accepts a license key. The ID is exactly one unsigned
// 64-bit big-endian database identifier; zero is invalid, even for trials.
func LicenseWatermark(private []byte, licenseID uint64) (string, error) {
	if len(private) != 32 || licenseID == 0 {
		return "", ErrInvalid
	}
	key, err := hkdf.Key(sha256.New, private, nil, "authgo/watermark/key/v1", 32)
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(key)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], licenseID)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(id[:])
	value := mac.Sum(nil)
	defer clear(value)
	return hex.EncodeToString(value), nil
}

type WatermarkTagInfo struct {
	KeyID string `json:"key_id"`
	Tag   string `json:"tag"`
}
type WatermarkSource struct {
	IP         string    `json:"ip"`
	InstanceID string    `json:"instance_id"`
	CreatedAt  time.Time `json:"created_at"`
}
type WatermarkTrace struct {
	Found     bool              `json:"found"`
	LicenseID uint64            `json:"license_id,omitempty"`
	UserID    *uint64           `json:"user_id,omitempty"`
	UserName  string            `json:"user_name,omitempty"`
	IsTrial   bool              `json:"is_trial,omitempty"`
	SourceIP  string            `json:"source_ip,omitempty"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	KeyID     string            `json:"key_id,omitempty"`
	Sources   []WatermarkSource `json:"sources,omitempty"`
}

func (s *Service) WatermarkTags(ctx context.Context, id uint64) ([]WatermarkTagInfo, error) {
	out := []WatermarkTagInfo{}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, e := findApp(tx, id); e != nil {
			return e
		}
		var keys []Key
		if e := tx.Select("key_id", "public_key").Where("app_id=?", id).Order("id ASC").Find(&keys).Error; e != nil {
			return e
		}
		for _, key := range keys {
			pub, e := b64(key.PublicKey)
			if e != nil {
				return ErrInvalid
			}
			tag, e := WatermarkTag(pub)
			if e != nil {
				return e
			}
			out = append(out, WatermarkTagInfo{key.KeyID, tag})
		}
		return nil
	})
	return out, err
}

// WatermarkForLicense must be called inside the already-authorized gateway
// transaction, after the envelope, license, instance and window checks.
func (s *Service) WatermarkForLicense(tx *gorm.DB, app model.Application, keyID string, licenseID uint64) (string, error) {
	var row Key
	if e := tx.Where("app_id=? AND key_id=?", app.ID, keyID).First(&row).Error; e != nil {
		return "", ErrInvalid
	}
	raw, e := s.cipher.Decrypt(row.PrivateKeyEncrypted, aad(app.AppKey, row.KeyID))
	if e != nil {
		return "", ErrInvalid
	}
	defer clear(raw)
	return LicenseWatermark(raw, licenseID)
}

func (s *Service) TraceWatermark(ctx context.Context, id uint64, value string) (WatermarkTrace, error) {
	result := WatermarkTrace{}
	if !watermarkPattern.MatchString(value) || value == "0000000000000000000000000000000000000000000000000000000000000000" {
		return result, apperror.Invalid("请输入64位小写十六进制非零水印值")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		app, e := findApp(tx, id)
		if e != nil {
			return e
		}
		var keys []Key
		if e = tx.Where("app_id=?", id).Order("id ASC").Find(&keys).Error; e != nil {
			return e
		}
		// Fixed query count: one app, one key list, one license list, at most one
		// batched user preload and one source query. Never query once per license.
		var licenses []model.License
		if e = tx.Select("id", "user_id", "type", "source", "created_at").Where("app_id=?", id).Preload("User", func(q *gorm.DB) *gorm.DB { return q.Select("id", "name") }).Order("id ASC").Find(&licenses).Error; e != nil {
			return e
		}
		matches := 0
		for _, key := range keys {
			raw, err := s.cipher.Decrypt(key.PrivateKeyEncrypted, aad(app.AppKey, key.KeyID))
			if err != nil {
				return ErrInvalid
			}
			for _, license := range licenses {
				candidate, err := LicenseWatermark(raw, license.ID)
				if err != nil {
					clear(raw)
					return err
				}
				if subtle.ConstantTimeCompare([]byte(candidate), []byte(value)) != 1 {
					continue
				}
				matches++
				result = WatermarkTrace{Found: true, LicenseID: license.ID, UserID: license.UserID, IsTrial: license.Type == "trial" || license.Source == "self_trial", KeyID: key.KeyID}
				if license.User != nil {
					result.UserName = license.User.Name
				}
				created := license.CreatedAt
				result.CreatedAt = &created
			}
			clear(raw)
		}
		if matches > 1 {
			return errors.New("ambiguous watermark match")
		}
		if result.Found {
			var sources []struct {
				IPKey      string
				InstanceID string
				CreatedAt  time.Time
			}
			if e = tx.Table("trial_claims").Select("ip_key", "instance_id", "created_at").Where("app_id=? AND license_id=?", id, result.LicenseID).Order("created_at ASC, id ASC").Find(&sources).Error; e != nil {
				return e
			}
			for _, source := range sources {
				result.Sources = append(result.Sources, WatermarkSource{source.IPKey, source.InstanceID, source.CreatedAt})
			}
			if len(sources) > 0 {
				result.SourceIP = sources[0].IPKey
			}
		}
		return nil
	})
	if err != nil {
		return WatermarkTrace{}, err
	}
	return result, nil
}
