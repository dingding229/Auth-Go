package automation

import (
	"authgo/internal/apperror"
	"authgo/internal/code"
	"authgo/internal/config"
	"authgo/internal/integration"
	"authgo/internal/mailer"
	"authgo/internal/model"
	"authgo/internal/netpolicy"
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

type SMTP struct {
	Enabled           bool   `json:"enabled"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
	From              string `json:"from"`
	Mode              string `json:"mode"`
	PasswordEncrypted string `json:"password_encrypted,omitempty"`
	HasPassword       bool   `json:"has_password"`
}
type Settings struct {
	TrialDays                 int      `json:"trial_days"`
	PublicURL                 string   `json:"public_url"`
	NotificationRetentionDays int      `json:"notification_retention_days"`
	AdminNotificationEmails   []string `json:"admin_notification_emails"`
	SiteName                  string   `json:"site_name"`
	TrustedProxies            []string `json:"trusted_proxies"`
	IPQueryRate               int      `json:"client_ip_rate"`
	IPBurst                   int      `json:"client_ip_burst"`
	LicenseRate               int      `json:"client_license_rate"`
	LicenseBurst              int      `json:"client_license_burst"`
	LogRetentionDays          int      `json:"log_retention_days"`
	SMTP                      SMTP     `json:"smtp"`
	proxies                   []netip.Prefix
}
type SMTPInput struct {
	Enabled  *bool   `json:"enabled"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	From     *string `json:"from"`
	Mode     *string `json:"mode"`
}
type SettingsInput struct {
	TrialDays                 *int       `json:"trial_days" minimum:"1" maximum:"365" default:"14"`
	PublicURL                 *string    `json:"public_url"`
	NotificationRetentionDays *int       `json:"notification_retention_days"`
	AdminNotificationEmails   *[]string  `json:"admin_notification_emails"`
	SiteName                  *string    `json:"site_name"`
	TrustedProxies            *[]string  `json:"trusted_proxies"`
	IPRate                    *int       `json:"client_ip_rate"`
	IPBurst                   *int       `json:"client_ip_burst"`
	LicenseRate               *int       `json:"client_license_rate"`
	LicenseBurst              *int       `json:"client_license_burst"`
	LogRetentionDays          *int       `json:"log_retention_days"`
	SMTP                      *SMTPInput `json:"smtp"`
}

func clean(v string, max int) bool {
	return len(v) <= max && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validateSettings(v *Settings) error {
	if v.TrialDays < 1 || v.TrialDays > 365 {
		return apperror.Invalid("试用天数必须为1至365")
	}
	if v.PublicURL != "" {
		normalized, err := integration.NormalizeURL(v.PublicURL)
		if err != nil {
			return apperror.Invalid("对外访问地址格式无效")
		}
		v.PublicURL = normalized
	}
	if v.NotificationRetentionDays < 1 || v.NotificationRetentionDays > 3650 {
		return apperror.Invalid("通知保留天数必须为1至3650")
	}
	if len(v.AdminNotificationEmails) > 50 {
		return apperror.Invalid("管理员通知邮箱最多50个")
	}
	seen := map[string]bool{}
	emails := []string{}
	for _, raw := range v.AdminNotificationEmails {
		email := strings.ToLower(strings.TrimSpace(raw))
		if _, e := mailer.Address(email); e != nil {
			return apperror.Invalid("管理员通知邮箱无效")
		}
		if !seen[email] {
			emails = append(emails, email)
			seen[email] = true
		}
	}
	v.AdminNotificationEmails = emails
	if strings.TrimSpace(v.SiteName) == "" || !clean(v.SiteName, 128) {
		return apperror.Invalid("站点名称无效")
	}
	for _, n := range []int{v.IPQueryRate, v.IPBurst, v.LicenseRate, v.LicenseBurst} {
		if n < 1 || n > 100000 {
			return apperror.Invalid("限流参数必须为1至100000")
		}
	}
	if v.IPBurst < v.IPQueryRate || v.LicenseBurst < v.LicenseRate {
		return apperror.Invalid("突发容量不能小于对应的速率")
	}
	if v.LogRetentionDays < 1 || v.LogRetentionDays > 3650 {
		return apperror.Invalid("日志保留天数无效")
	}
	if len(v.TrustedProxies) > 1000 {
		return apperror.Invalid("受信代理配置过多")
	}
	v.proxies = nil
	for _, raw := range v.TrustedProxies {
		if ip, e := netip.ParseAddr(raw); e == nil {
			if ip.Zone() != "" {
				return apperror.Invalid("受信代理不能包含 zone")
			}
			ip = ip.Unmap()
			v.proxies = append(v.proxies, netip.PrefixFrom(ip, ip.BitLen()))
		} else {
			p, e := netip.ParsePrefix(raw)
			if e != nil {
				return apperror.Invalid("受信代理必须为 IP 或 CIDR")
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return apperror.Invalid("IPv4 映射代理网段必须至少为 /96")
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			v.proxies = append(v.proxies, p.Masked())
		}
	}
	if e := mailer.Validate(mailer.Config{Enabled: v.SMTP.Enabled, Host: v.SMTP.Host, Port: v.SMTP.Port, Username: v.SMTP.Username, From: v.SMTP.From, Mode: v.SMTP.Mode}); e != nil {
		return apperror.Invalid(e.Error())
	}
	return nil
}
func (s *Service) loadSettings(cfg config.Config) error {
	v := Settings{TrialDays: 14, PublicURL: cfg.PublicURL, NotificationRetentionDays: 30, AdminNotificationEmails: []string{}, SiteName: "Auth Go", TrustedProxies: append([]string{}, cfg.TrustedProxies...), IPQueryRate: cfg.ClientIPRate, IPBurst: cfg.ClientIPBurst, LicenseRate: cfg.ClientLicenseRate, LicenseBurst: cfg.ClientLicenseBurst, LogRetentionDays: 90, SMTP: SMTP{Port: 587, Mode: "starttls"}}
	if v.IPQueryRate == 0 {
		v.IPQueryRate = 10
	}
	if v.IPBurst == 0 {
		v.IPBurst = 60
	}
	if v.LicenseRate == 0 {
		v.LicenseRate = 5
	}
	if v.LicenseBurst == 0 {
		v.LicenseBurst = 30
	}
	var row model.Setting
	e := s.db.First(&row, "key=?", "system.v1").Error
	if e == nil {
		if e := json.Unmarshal([]byte(row.Value), &v); e != nil {
			return e
		}
	} else if !errors.Is(e, gorm.ErrRecordNotFound) {
		return e
	}
	if v.PublicURL == "" {
		v.PublicURL = cfg.PublicURL
	}
	if e := validateSettings(&v); e != nil {
		return e
	}
	s.settings.Store(&v)
	return nil
}
func (s *Service) Current() Settings {
	v := *s.settings.Load()
	v.AdminNotificationEmails = append([]string{}, v.AdminNotificationEmails...)
	v.TrustedProxies = append([]string{}, v.TrustedProxies...)
	v.proxies = append([]netip.Prefix(nil), v.proxies...)
	return v
}
func (s *Service) PublicSettings() Settings {
	v := s.Current()
	v.SMTP.HasPassword = v.SMTP.PasswordEncrypted != ""
	v.SMTP.PasswordEncrypted = ""
	return v
}
func (s *Service) UpdateSettings(ctx context.Context, in SettingsInput) (Settings, error) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	v := s.Current()
	if in.TrialDays != nil {
		v.TrialDays = *in.TrialDays
	}
	if in.PublicURL != nil {
		v.PublicURL = strings.TrimSpace(*in.PublicURL)
	}
	if in.NotificationRetentionDays != nil {
		v.NotificationRetentionDays = *in.NotificationRetentionDays
	}
	if in.AdminNotificationEmails != nil {
		v.AdminNotificationEmails = append([]string{}, (*in.AdminNotificationEmails)...)
	}
	if in.SiteName != nil {
		v.SiteName = strings.TrimSpace(*in.SiteName)
	}
	if in.TrustedProxies != nil {
		v.TrustedProxies = append([]string{}, (*in.TrustedProxies)...)
	}
	for _, field := range []struct {
		input *int
		dst   *int
	}{{in.IPRate, &v.IPQueryRate}, {in.IPBurst, &v.IPBurst}, {in.LicenseRate, &v.LicenseRate}, {in.LicenseBurst, &v.LicenseBurst}, {in.LogRetentionDays, &v.LogRetentionDays}} {
		if field.input != nil {
			*field.dst = *field.input
		}
	}

	if smtp := in.SMTP; smtp != nil {
		if smtp.Enabled != nil {
			v.SMTP.Enabled = *smtp.Enabled
		}
		if smtp.Host != nil {
			v.SMTP.Host = *smtp.Host
		}
		if smtp.Port != nil {
			v.SMTP.Port = *smtp.Port
		}
		if smtp.Username != nil {
			v.SMTP.Username = *smtp.Username
		}
		if smtp.From != nil {
			v.SMTP.From = *smtp.From
		}
		if smtp.Mode != nil {
			v.SMTP.Mode = *smtp.Mode
		}
		if smtp.Password != nil {
			if len(*smtp.Password) > 1024 {
				return Settings{}, apperror.Invalid("SMTP 密码过长")
			}
			v.SMTP.PasswordEncrypted = ""
			if *smtp.Password != "" {
				encrypted, e := s.cipher.Encrypt([]byte(*smtp.Password), []byte("authgo/system/smtp-password/v1"))
				if e != nil {
					return Settings{}, e
				}
				v.SMTP.PasswordEncrypted = encrypted
			}
		}
	}
	if e := validateSettings(&v); e != nil {
		return Settings{}, e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return Settings{}, e
	}
	e = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&model.Setting{Key: "system.v1", Value: string(raw)}).Error; e != nil {
			return e
		}
		return nil
	})
	if e != nil {
		return Settings{}, e
	}
	s.settings.Store(&v)
	if s.apply != nil {
		s.apply(v)
	}
	return s.PublicSettings(), nil
}

// TrustsProxy checks the immediate peer for all forwarded metadata.
func (s *Service) TrustsProxy(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && s.trustedProxy(ip.WithZone("").Unmap())
}

func (s *Service) trustedProxy(ip netip.Addr) bool {
	v := s.settings.Load()

	if len(v.TrustedProxies) == 0 {
		return netpolicy.InternalPeer(ip)
	}

	for _, p := range v.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) ResolveIP(remote, xff, real string) string {
	return netpolicy.ResolveClientIP(remote, xff, real, s.trustedProxy)
}

func (s *Service) smtpConfig() (mailer.Config, error) {
	v := s.Current().SMTP
	password := ""
	if v.PasswordEncrypted != "" {
		raw, e := s.cipher.Decrypt(v.PasswordEncrypted, []byte("authgo/system/smtp-password/v1"))
		if e != nil {
			return mailer.Config{}, e
		}
		password = string(raw)
	}
	return mailer.Config{Enabled: v.Enabled, Host: v.Host, Port: v.Port, Username: v.Username, Password: password, From: v.From, Mode: v.Mode}, nil
}
func (s *Service) TestMail(ctx context.Context, to string) error {
	cfg, e := s.smtpConfig()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return apperror.New(409, code.SMTPNotConfigured, "SMTP 尚未启用")
	}
	if _, e := mailer.Address(to); e != nil {
		return apperror.Invalid(e.Error())
	}
	if e := s.sendMail(ctx, cfg, mailer.Message{To: to, Subject: "【" + s.Current().SiteName + "】测试邮件", Body: "这是一封 Auth Go SMTP 配置测试邮件。"}); e != nil {
		return apperror.New(502, code.SMTPSendFailed, "测试邮件发送失败，请检查 SMTP 配置")
	}
	return nil
}

// SendPortalCode is for portal; this does not generate, store or verify login codes.
func (s *Service) SendPortalCode(ctx context.Context, to, verificationCode string, expires time.Time) error {
	cfg, e := s.smtpConfig()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return apperror.New(409, code.SMTPNotConfigured, "SMTP 尚未启用")
	}
	if !expires.After(s.now()) || expires.After(s.now().Add(time.Hour)) {
		return apperror.Invalid("验证码到期时间无效")
	}
	if _, e := mailer.Address(to); e != nil {
		return apperror.Invalid(e.Error())
	}
	m, e := mailer.PortalCode(s.Current().SiteName, to, verificationCode, expires)
	if e != nil {
		return e
	}
	return s.sendMail(ctx, cfg, m)
}
