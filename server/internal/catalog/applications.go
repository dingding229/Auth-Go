package catalog

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/integration"
	"authgo/internal/model"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"gorm.io/gorm"
	"regexp"
	"strings"
)

type ApplicationInfo struct {
	HeartbeatInterval int `json:"heartbeat_interval"`
	BaseInfo
	DockerImage       string `json:"docker_image"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	AppKey            string `json:"app_key"`
	PublicKey         string `json:"public_key"`
	PreviousPublicKey string `json:"previous_public_key"`
	Status            string `json:"status"`
	NextCheckIn       int    `json:"next_check_in"`
	GraceHours        int    `json:"grace_hours"`
	TrialEnabled      bool   `json:"trial_enabled"`
	TrialDays         int    `json:"trial_days"`
}

func applicationInfo(a model.Application) ApplicationInfo {
	return ApplicationInfo{a.HeartbeatInterval, baseInfo(a.Base), a.DockerImage, a.Name, a.Description, a.AppKey, a.PublicKey, a.PreviousPublicKey, a.Status, a.NextCheckIn, a.GraceHours, a.TrialEnabled, a.TrialDays}
}

type ApplicationInput struct {
	HeartbeatInterval *int    `json:"heartbeat_interval"`
	DockerImage       *string `json:"docker_image"`
	Name              *string `json:"name"`
	Description       *string `json:"description"`
	Status            *string `json:"status"`
	NextCheckIn       *int    `json:"next_check_in"`
	GraceHours        *int    `json:"grace_hours"`
}

func (in ApplicationInput) empty() bool {
	return in.DockerImage == nil && in.HeartbeatInterval == nil && in.Name == nil && in.Description == nil && in.Status == nil && in.NextCheckIn == nil && in.GraceHours == nil
}
func applyApplication(a model.Application, in ApplicationInput) (model.Application, error) {
	if in.DockerImage != nil {
		a.DockerImage = strings.TrimSpace(*in.DockerImage)
		if len(a.DockerImage) > 255 || a.DockerImage != "" && !regexp.MustCompile(`^(docker\.io/)?[a-z0-9][a-z0-9_-]*/[a-z0-9]+([._-]+[a-z0-9]+)*$`).MatchString(a.DockerImage) {
			return a, apperror.Invalid("Docker Hub镜像名应为小写的命名空间/镜像名，不含标签或凭据")
		}
	}
	if in.HeartbeatInterval != nil {
		a.HeartbeatInterval = *in.HeartbeatInterval
	}
	if in.Name != nil {
		a.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		a.Description = *in.Description
	}
	if in.Status != nil {
		a.Status = *in.Status
	}
	if in.NextCheckIn != nil {
		a.NextCheckIn = *in.NextCheckIn
	}
	if in.GraceHours != nil {
		a.GraceHours = *in.GraceHours
	}

	if !validName(a.Name) {
		return a, apperror.Invalid("软件名称不能为空、包含控制字符或超过 128 字节")
	}
	if len(a.Description) > 4096 {
		return a, apperror.Invalid("软件说明不得超过 4096 字节")
	}
	if a.Status != "active" && a.Status != "disabled" {
		return a, apperror.Invalid("软件状态必须为 active 或 disabled")
	}
	if a.HeartbeatInterval < 5 || a.HeartbeatInterval > 3600 {
		return a, apperror.Invalid("heartbeat_interval 必须为 5 至 3600 秒")
	}
	if a.NextCheckIn < 1 || a.NextCheckIn > 86400 {
		return a, apperror.Invalid("next_check_in 必须为 1 至 86400 秒")
	}
	if a.GraceHours < 0 || a.GraceHours > 8760 {
		return a, apperror.Invalid("grace_hours 必须为 0 至 8760 小时")
	}

	return a, nil
}
func publicApplicationFields(a model.Application) map[string]any {
	return map[string]any{
		"docker_image": a.DockerImage, "heartbeat_interval": a.HeartbeatInterval, "name": a.Name, "description": a.Description, "status": a.Status, "next_check_in": a.NextCheckIn, "grace_hours": a.GraceHours,
	}
}
func (s *Service) CreateApplication(ctx context.Context, in ApplicationInput) (ApplicationInfo, error) {
	defaults := model.Application{HeartbeatInterval: 60, Status: "active", NextCheckIn: 3600, GraceHours: 72}

	a, err := applyApplication(defaults, in)
	if err != nil {
		return ApplicationInfo{}, err
	}
	key, err := cryptoutil.RandomString(32)
	if err != nil {
		return ApplicationInfo{}, err
	}
	a.AppKey = "app_" + key
	secret, err := cryptoutil.RandomString(32)
	if err != nil {
		return ApplicationInfo{}, err
	}
	a.AppSecretEncrypted, err = s.cipher.Encrypt([]byte(secret), aad(a.AppKey, "app_secret"))
	if err != nil {
		return ApplicationInfo{}, err
	}
	public, private, err := cryptoutil.GenerateEd25519()
	if err != nil {
		return ApplicationInfo{}, err
	}
	a.PublicKey = base64.StdEncoding.EncodeToString(public)
	a.PrivateKeyEncrypted, err = s.cipher.Encrypt(private, aad(a.AppKey, "ed25519_private_key"))
	if err != nil {
		return ApplicationInfo{}, err
	}
	fields := publicApplicationFields(a)
	now := s.db.NowFunc()
	fields["created_at"] = now
	fields["updated_at"] = now
	fields["app_key"] = a.AppKey
	fields["app_secret_encrypted"] = a.AppSecretEncrypted
	fields["public_key"] = a.PublicKey
	fields["private_key_encrypted"] = a.PrivateKeyEncrypted
	fields["previous_public_key"] = ""
	// Explicit map values preserve grace_hours=0, rather than GORM replacing it
	// with the model's nonzero default. No plaintext credentials enter this map.
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Application{}).Create(fields).Error; err != nil {
			return err
		}
		return tx.Where("app_key = ?", a.AppKey).First(&a).Error
	})
	if err == nil {
		a, err = s.channel.EnsureApplication(ctx, a.ID)
	}
	return applicationInfo(a), err
}
func (s *Service) UpdateApplication(ctx context.Context, id uint64, in ApplicationInput) (ApplicationInfo, error) {
	if in.empty() {
		return ApplicationInfo{}, apperror.Invalid("至少提供一个修改字段")
	}
	var result model.Application
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := application(tx, id)
		if err != nil {
			return err
		}
		a, err = applyApplication(a, in)
		if err != nil {
			return err
		}
		if err := tx.Model(&model.Application{}).Where("id = ?", id).Updates(publicApplicationFields(a)).Error; err != nil {
			return err
		}
		result, err = application(tx, id)
		return err
	})
	return applicationInfo(result), err
}
func (s *Service) RevealSecret(ctx context.Context, id uint64) (string, error) {
	a, err := application(s.db.WithContext(ctx), id)
	if err != nil {
		return "", err
	}
	secret, err := s.cipher.Decrypt(a.AppSecretEncrypted, aad(a.AppKey, "app_secret"))
	return string(secret), err
}
func (s *Service) RotateSecret(ctx context.Context, id uint64) (ApplicationInfo, error) {
	var result model.Application
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := application(tx, id)
		if err != nil {
			return err
		}
		secret, err := cryptoutil.RandomString(32)
		if err != nil {
			return err
		}
		encrypted, err := s.cipher.Encrypt([]byte(secret), aad(a.AppKey, "app_secret"))
		if err != nil {
			return err
		}
		if err := tx.Model(&model.Application{}).Where("id = ?", id).Update("app_secret_encrypted", encrypted).Error; err != nil {
			return err
		}
		result, err = application(tx, id)
		return err
	})
	return applicationInfo(result), err
}
func (s *Service) RotateKeyPair(ctx context.Context, id uint64) (ApplicationInfo, error) {
	var result model.Application
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := application(tx, id)
		if err != nil {
			return err
		}
		public, private, err := cryptoutil.GenerateEd25519()
		if err != nil {
			return err
		}
		encrypted, err := s.cipher.Encrypt(private, aad(a.AppKey, "ed25519_private_key"))
		if err != nil {
			return err
		}
		if err := tx.Model(&model.Application{}).Where("id = ?", id).Updates(map[string]any{"previous_public_key": a.PublicKey, "public_key": base64.StdEncoding.EncodeToString(public), "private_key_encrypted": encrypted}).Error; err != nil {
			return err
		}
		result, err = application(tx, id)
		return err
	})
	return applicationInfo(result), err
}
func (s *Service) PublicKeyPEM(ctx context.Context, id uint64, previous bool) ([]byte, error) {
	a, err := application(s.db.WithContext(ctx), id)
	if err != nil {
		return nil, err
	}
	encoded := a.PublicKey
	if previous {
		encoded = a.PreviousPublicKey
	}
	if encoded == "" {
		return nil, apperror.New(404, "NOT_FOUND", "没有可下载的上一版公钥")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return cryptoutil.PublicKeyPEM(ed25519.PublicKey(key))
}
func (s *Service) DeleteApplication(ctx context.Context, id uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := application(tx, id)
		if err != nil {
			return err
		}
		for _, relation := range []struct {
			entity any
			label  string
		}{{&model.License{}, "授权"}, {&model.VerifyLog{}, "验证日志"}, {&model.Announcement{}, "公告"}, {&model.AppVersion{}, "版本记录"}} {
			used, err := exists(tx, relation.entity, "app_id", id)
			if err != nil {
				return err
			}
			if used {
				return inUse("软件仍有关联" + relation.label + "，不能删除")
			}
		}
		// Templates are configuration snapshots, not dependencies of issued licenses.
		if err := tx.Model(&a).Update("trial_template_id", nil).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM feature_templates WHERE app_id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM payload_keys WHERE app_id = ?", id).Error; err != nil {
			return err
		}
		return deleteError(tx.Delete(&a).Error, "软件有关联数据，不能删除")
	})
}

// ConnectionConfig reveals only the same secret available through RevealSecret.
// The management router must audit this operation before calling it.
func (s *Service) ConnectionConfig(ctx context.Context, id uint64, url string) (string, error) {
	a, err := application(s.db.WithContext(ctx), id)
	if err != nil {
		return "", err
	}
	secret, err := s.cipher.Decrypt(a.AppSecretEncrypted, aad(a.AppKey, "app_secret"))
	if err != nil {
		return "", err
	}
	key, err := s.channel.Current(ctx)
	if err != nil {
		return "", err
	}
	return integration.Encode(integration.Config{URL: url, AppKey: a.AppKey, AppSecret: string(secret), PublicKey: a.PublicKey, GatewayKey: key.PublicKey})
}
