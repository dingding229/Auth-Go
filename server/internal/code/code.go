// Package code is the stable client/portal error-code vocabulary.
package code

const (
	TrialDisabled          = "TRIAL_DISABLED"
	TrialIPLimit           = "TRIAL_IP_LIMIT"
	TrialQuotaExceeded     = "TRIAL_QUOTA_EXCEEDED"
	PortalUnauthorized     = "PORTAL_UNAUTHORIZED"
	CodeCooldown           = "CODE_COOLDOWN"
	OK                     = "OK"
	UserDisabled           = "USER_DISABLED"
	SMTPNotConfigured      = "SMTP_NOT_CONFIGURED"
	SMTPSendFailed         = "SMTP_SEND_FAILED"
	InvalidRequest         = "INVALID_REQUEST"
	PayloadInvalid         = "PAYLOAD_INVALID"
	InvalidLicenseKey      = "INVALID_LICENSE_KEY"
	AppNotFound            = "APP_NOT_FOUND"
	AppDisabled            = "APP_DISABLED"
	LicenseNotFound        = "LICENSE_NOT_FOUND"
	LicenseNotActivated    = "LICENSE_NOT_ACTIVATED"
	LicenseExpired         = "LICENSE_EXPIRED"
	LicenseNotStarted      = "LICENSE_NOT_STARTED"
	LicenseSuspended       = "LICENSE_SUSPENDED"
	LicenseRevoked         = "LICENSE_REVOKED"
	InvalidPolicy          = "INVALID_POLICY"
	InstanceReplaced       = "INSTANCE_REPLACED"
	VersionDisabled        = "VERSION_DISABLED"
	MaintenanceExpired     = "MAINTENANCE_EXPIRED"
	VersionNotAllowed      = "VERSION_NOT_ALLOWED"
	DeviceInvalid          = "DEVICE_INVALID"
	FloatingLimitReached   = "FLOATING_LIMIT_REACHED"
	LeaseExpired           = "LEASE_EXPIRED"
	ActivationInvalid      = "ACTIVATION_INVALID"
	ActivationLimitReached = "ACTIVATION_LIMIT_REACHED"
	SignatureInvalid       = "SIGNATURE_INVALID"
	TimestampInvalid       = "TIMESTAMP_INVALID"
	ReplayDetected         = "REPLAY_DETECTED"
	RateLimited            = "RATE_LIMITED"
	VersionNotFound        = "VERSION_NOT_FOUND"
	InternalError          = "INTERNAL_ERROR"
)

type Description struct {
	Status  int
	Message string
}

var descriptions = map[string]Description{
	PayloadInvalid:       {422, "加密载荷无效，请联系提供方重新构建"},
	TrialDisabled:        {403, "此软件未开放试用，请设置AUTHGO_LICENSE授权码后启动"},
	TrialIPLimit:         {403, "此网络已领取过试用，请设置AUTHGO_LICENSE或联系提供方"},
	TrialQuotaExceeded:   {403, "今日试用名额已用完，请稍后重试或联系提供方"},
	VersionNotAllowed:    {403, "当前程序版本不在授权允许范围内，请联系提供方"},
	DeviceInvalid:        {400, "设备指纹无效，请检查程序的实例指纹配置"},
	FloatingLimitReached: {403, "运行实例数已达授权上限，请停止其他实例或联系提供方"},
	LeaseExpired:         {403, "实例席位已过期，请重新校验授权"},
	InstanceReplaced:     {403, "此实例已被新的进程接管"}, VersionDisabled: {403, "当前版本已禁用，请更新程序"}, MaintenanceExpired: {403, "当前授权的更新维护期已结束，此版本需要续期"},
	UserDisabled:       {403, "用户已停用，请联系管理员"},
	PortalUnauthorized: {401, "用户中心登录凭据无效或已过期"},
	CodeCooldown:       {429, "同一邮箱发送验证码需间隔60秒"},
	SMTPNotConfigured:  {409, "SMTP 尚未启用"},
	SMTPSendFailed:     {502, "测试邮件发送失败，请检查 SMTP 配置"},
	OK:                 {200, "验证成功"}, InvalidRequest: {400, "请求格式无效"}, InvalidLicenseKey: {400, "授权码格式或校验位无效"}, AppNotFound: {404, "软件不存在"}, AppDisabled: {403, "软件已停用"},
	LicenseNotFound: {404, "授权不存在"}, LicenseNotActivated: {403, "授权尚未激活"}, LicenseExpired: {403, "授权已到期"}, LicenseNotStarted: {403, "授权尚未生效"}, LicenseSuspended: {403, "授权已暂停"}, LicenseRevoked: {403, "授权已吊销"}, InvalidPolicy: {403, "授权策略配置无效"},
	ActivationInvalid: {401, "激活凭据无效或已失效"}, ActivationLimitReached: {403, "客户端会话数量已达上限"}, SignatureInvalid: {401, "请求签名无效"}, TimestampInvalid: {401, "请求时间戳无效或超出允许范围"}, ReplayDetected: {409, "请求 nonce 已使用"}, RateLimited: {429, "请求过于频繁"}, VersionNotFound: {404, "没有已发布版本"}, InternalError: {500, "服务器内部错误"},
}

func Describe(value string) Description {
	if d, ok := descriptions[value]; ok {
		return d
	}
	return descriptions[InternalError]
}
