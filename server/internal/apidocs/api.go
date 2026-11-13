// Package apidocs contains the API contract annotations and generated OpenAPI 3.1 document.
// The router coverage test prevents an implemented route from silently missing documentation.
package apidocs

import (
	"authgo/internal/automation"
	"authgo/internal/catalog"
	"authgo/internal/dockerhub"
	"authgo/internal/enduser"
	"authgo/internal/ipinfo"
	"authgo/internal/licensing"
	"authgo/internal/maintenance"

	"authgo/internal/payloadkey"
	"authgo/internal/portal"
	"authgo/internal/sharing"
	"authgo/internal/template"
	"authgo/internal/trial"
	"authgo/internal/updater"
	"time"
)

// @title Auth Go API
// @version 1.0.0
// @description 单团队 SQLite 授权服务。管理端 Bearer access JWT；用户中心使用授权范围 portal JWT；客户端仅使用v2加密入口。响应 data 的详细业务字段及规则见 README.md 的使用教程与错误码章节，错误码见 README.md#错误码。
// @description users：用户通过end_users关联授权；管理API /users，用户中心/portal/user/login和/switch，具体约束见README.md#使用教程。
// @description 管理端统一使用唯一管理员的 JWT。时间使用 UTC RFC3339，分页为 page/page_size/total。
// @description 未认证管理请求按来源限流（IPv6按/64归并，突发30次、每秒恢复5次），超出返回429 RATE_LIMITED；未认证或未匹配路由不写同步审计。已认证敏感操作先写审计意图，失败返回503 AUDIT_UNAVAILABLE且不执行操作；审计固定保留365天并每日清理。
// @servers.url /
// @securityDefinitions.apikey AdminBearer
// @in header
// @name Authorization
// @description Bearer <管理员 access JWT>。
func AdminSecurity() {}

// @securityDefinitions.apikey PortalBearer
// @in header
// @name Authorization
// @description Bearer <portal_token>，有效 2 小时，不能访问管理端。用户作用域仅访问当前用户名下数据；授权码作用域仅访问当前授权，不能调用用户接口。
func PortalSecurity() {}

// Envelope is the common API response. Signature may be null for admin and early errors.
type Envelope struct {
	Code      string `json:"code" example:"OK"`
	Message   string `json:"message" example:"操作成功"`
	Data      any    `json:"data"`
	Signature any    `json:"signature"`
	TS        int64  `json:"ts,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

type Health struct {
	Status string `json:"status" example:"ok"`
}

// @Summary 服务与数据库健康检查
// @Tags 健康检查
// @Produce json
// @Success 200 {object} Health
// @Failure 503 {object} Health
// @Router /healthz [get]
// @Router /healthz [head]
func Healthz() {}

type AutomationSettingsInput = automation.SettingsInput
type CatalogAnnouncementInput = catalog.AnnouncementInput
type CatalogApplicationInput = catalog.ApplicationInput
type CatalogVersionInput = catalog.VersionInput
type LicensingBatchInput = licensing.BatchInput
type MaintenanceInput = maintenance.Input
type TrialSettings = trial.Settings
type FeatureTemplateInput = template.Input
type FeatureTemplateInfo = template.Info
type TrialConversion = trial.ConvertInput
type LicensingCreateInput = licensing.CreateInput
type LicensingRenewInput = licensing.RenewInput
type PortalLoginInput = portal.LoginInput

type AdminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type AdminRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type SetupTOTPRequest struct {
	Password string `json:"password"`
}

type EnableTOTPRequest struct {
	TOTPCode string `json:"totp_code"`
}

type DisableTOTPRequest struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type PortalPasswordRequest struct {
	Password *string `json:"password"`
}

type SMTPTestRequest struct {
	To string `json:"to"`
}

type PortalCodeRequest struct {
	LicenseKey string `json:"license_key"`
	Email      string `json:"email"`
}

// @Summary 管理员认证 POST /auth/login
// @Description 失败按用户名+来源计数（IPv6按/64归并），5次失败暂停该来源15分钟；同一用户名跨来源20次失败后暂停至当前15分钟固定窗口结束。受限请求不延长账号窗口，成功登录清除失败预算；返回429 LOGIN_LOCKED，不永久锁定账号。
// @Tags 管理员认证
// @Produce json
// @Accept json
// @Param body body AdminLoginRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/login [post]
func PostAdminAuthLogin() {}

// @Summary 管理员认证 POST /auth/refresh
// @Tags 管理员认证
// @Produce json
// @Accept json
// @Param body body AdminRefreshRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/refresh [post]
func PostAdminAuthRefresh() {}

// @Summary 管理员认证 GET /auth/me
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/me [get]
func GetAdminAuthMe() {}

// @Summary 管理员认证 POST /auth/logout
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/logout [post]
func PostAdminAuthLogout() {}

// @Summary 管理员认证 POST /auth/password
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body ChangePasswordRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/password [post]
func PostAdminAuthPassword() {}

// @Summary 管理员认证 POST /auth/totp/setup
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body SetupTOTPRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/totp/setup [post]
func PostAdminAuthTotpSetup() {}

// @Summary 管理员认证 POST /auth/totp/enable
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body EnableTOTPRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/totp/enable [post]
func PostAdminAuthTotpEnable() {}

// @Summary 管理员认证 POST /auth/totp/disable
// @Tags 管理员认证
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body DisableTOTPRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/auth/totp/disable [post]
func PostAdminAuthTotpDisable() {}

// @Summary 审计日志 GET /audit-logs
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 审计日志
// @Produce json
// @Security AdminBearer
// @Param admin_id query string false "admin_id；规则见接口契约"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param status_code query string false "status_code；规则见接口契约"
// @Param action query string false "action；规则见接口契约"
// @Param resource query string false "resource；规则见接口契约"
// @Param resource_id query string false "resource_id；规则见接口契约"
// @Param ip query string false "ip；规则见接口契约"
// @Param operator query string false "operator；规则见接口契约"
// @Param from query string false "from；规则见接口契约"
// @Param to query string false "to；规则见接口契约"
// @Success 200 {object} AuditLogResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/audit-logs [get]
func GetAdminAuditLogs() {}

// @Summary 软件 GET /applications
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param q query string false "关键字（最多128字节）"
// @Param sort_order query string false "asc / desc，默认desc"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "排序字段；允许值见接口契约"
// @Param status query string false "status；规则见接口契约"
// @Success 200 {object} Envelope{data=ApplicationList} "含docker_image与断网行为设置"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications [get]
func GetAdminApplications() {}

// @Summary 软件 POST /applications
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body catalog.ApplicationInput true "请求参数"
// @Success 200 {object} Envelope{data=catalog.ApplicationInfo} "含docker_image与断网行为设置"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications [post]
func PostAdminApplications() {}

// @Summary 软件 GET /applications/:id
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope{data=catalog.ApplicationInfo} "含docker_image与断网行为设置"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id} [get]
func GetAdminApplicationsId() {}

// @Summary 软件 PATCH /applications/:id
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body catalog.ApplicationInput true "请求参数"
// @Success 200 {object} Envelope{data=catalog.ApplicationInfo} "含docker_image与断网行为设置"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id} [patch]
func PatchAdminApplicationsId() {}

// @Summary 软件 DELETE /applications/:id
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id} [delete]
func DeleteAdminApplicationsId() {}

// @Summary 软件 GET /applications/:id/secret
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/secret [get]
func GetAdminApplicationsIdSecret() {}

// @Summary 软件 POST /applications/:id/rotate-secret
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/rotate-secret [post]
func PostAdminApplicationsIdRotateSecret() {}

// @Summary 软件 POST /applications/:id/rotate-key-pair
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/rotate-key-pair [post]
func PostAdminApplicationsIdRotateKeyPair() {}

// @Summary 软件 GET /applications/:id/public-key
// @Tags 软件
// @Security AdminBearer
// @Param id path string true "id"
// @Param previous query string false "previous；规则见接口契约"
// @Produce application/x-pem-file
// @Success 200 {string} string "下载文件（失败时返回JSON错误）"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/public-key [get]
func GetAdminApplicationsIdPublicKey() {}

// @Summary 授权 GET /licenses
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param app_id query string false "app_id；规则见接口契约"
// @Param batch_id query string false "batch_id；规则见接口契约"
// @Param expires_from query string false "expires_from；规则见接口契约"
// @Param expires_to query string false "expires_to；规则见接口契约"
// @Param q query string false "关键字（最多128字节）"
// @Param status query string false "status；规则见接口契约"
// @Param type query string false "type；规则见接口契约"
// @Param suspected_sharing query boolean false "仅显示未忽略的疑似共享；IP 库未启用时无匹配项"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "sort_by；规则见接口契约"
// @Param sort_order query string false "sort_order；规则见接口契约"
// @Success 200 {object} Envelope{data=LicenseList} "操作成功"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses [get]
func GetAdminLicenses() {}

// @Summary 授权 POST /licenses
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body licensing.CreateInput true "请求参数"
// @Param app_id query string false "app_id；规则见接口契约"
// @Param batch_id query string false "batch_id；规则见接口契约"
// @Param expires_from query string false "expires_from；规则见接口契约"
// @Param expires_to query string false "expires_to；规则见接口契约"
// @Param q query string false "关键字（最多128字节）"
// @Param status query string false "status；规则见接口契约"
// @Param type query string false "type；规则见接口契约"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses [post]
func PostAdminLicenses() {}

// @Summary 授权 POST /licenses/batch
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body licensing.BatchInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/batch [post]
func PostAdminLicensesBatch() {}

// @Summary 授权 GET /licenses/export
// @Tags 授权
// @Security AdminBearer
// @Param app_id query string false "app_id；规则见接口契约"
// @Param batch_id query string false "batch_id；规则见接口契约"
// @Param expires_from query string false "expires_from；规则见接口契约"
// @Param expires_to query string false "expires_to；规则见接口契约"
// @Param q query string false "关键字（最多128字节）"
// @Param status query string false "status；规则见接口契约"
// @Param type query string false "type；规则见接口契约"
// @Produce text/csv
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "sort_by；规则见接口契约"
// @Param sort_order query string false "sort_order；规则见接口契约"
// @Success 200 {string} string "下载文件（失败时返回JSON错误）"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/export [get]
func GetAdminLicensesExport() {}

// @Summary 授权 GET /licenses/batches/:batch_id/export
// @Tags 授权
// @Security AdminBearer
// @Param batch_id path string true "batch_id"
// @Param app_id query string false "app_id；规则见接口契约"
// @Param batch_id query string false "batch_id；规则见接口契约"
// @Param expires_from query string false "expires_from；规则见接口契约"
// @Param expires_to query string false "expires_to；规则见接口契约"
// @Param q query string false "关键字（最多128字节）"
// @Param status query string false "status；规则见接口契约"
// @Param type query string false "type；规则见接口契约"
// @Produce text/csv
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "sort_by；规则见接口契约"
// @Param sort_order query string false "sort_order；规则见接口契约"
// @Success 200 {string} string "下载文件（失败时返回JSON错误）"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/batches/{batch_id}/export [get]
func GetAdminLicensesBatchesBatchIdExport() {}

// @Summary 授权 POST /licenses/import
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Accept mpfd
// @Param file formData file true "CSV文件（最多16MiB）；也支持text/csv原始正文"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/import [post]
func PostAdminLicensesImport() {}

// @Summary 授权 GET /licenses/:id
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} LicenseDetailResponse "操作成功"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id} [get]
func GetAdminLicensesId() {}

// @Summary 授权 POST /licenses/:id/renew
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body licensing.RenewInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/renew [post]
func PostAdminLicensesIdRenew() {}

// @Summary 授权 POST /licenses/:id/suspend
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/suspend [post]
func PostAdminLicensesIdSuspend() {}

// @Summary 授权 POST /licenses/:id/resume
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/resume [post]
func PostAdminLicensesIdResume() {}

// @Summary 授权 POST /licenses/:id/revoke
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/revoke [post]
func PostAdminLicensesIdRevoke() {}

// @Summary 授权 POST /licenses/:id/portal-password
// @Tags 授权
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body PortalPasswordRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/portal-password [post]
func PostAdminLicensesIdPortalPassword() {}

// @Summary 授权 GET /licenses/:id/activations
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 授权
// @Param kind query string false "记录类型" Enums(floating,key)
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "sort_by；规则见接口契约"
// @Param sort_order query string false "sort_order；规则见接口契约"
// @Param q query string false "q；规则见接口契约"
// @Param license_id query string false "license_id；规则见接口契约"
// @Param app_id query string false "app_id；规则见接口契约"
// @Param status query string false "status；规则见接口契约"
// @Success 200 {object} ActivationListResponse "包含授权码的激活记录"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/activations [get]
func GetAdminLicensesIdActivations() {}

// @Summary 实例 GET /activations
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 实例
// @Param kind query string false "记录类型" Enums(floating,key)
// @Produce json
// @Security AdminBearer
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "sort_by；规则见接口契约"
// @Param sort_order query string false "sort_order；规则见接口契约"
// @Param q query string false "q；规则见接口契约"
// @Param license_id query string false "license_id；规则见接口契约"
// @Param app_id query string false "app_id；规则见接口契约"
// @Param status query string false "status；规则见接口契约"
// @Success 200 {object} ActivationListResponse "包含授权码的激活记录"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/activations [get]
func GetAdminActivations() {}

// @Summary 实例 POST /activations/:id/unbind
// @Tags 实例
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/activations/{id}/unbind [post]
func PostAdminActivationsIdUnbind() {}

// @Summary 软件 GET /applications/:id/announcements
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Param q query string false "关键字（最多128字节）"
// @Param sort_order query string false "asc / desc，默认desc"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "排序字段；允许值见接口契约"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/announcements [get]
func GetAdminApplicationsIdAnnouncements() {}

// @Summary 软件 POST /applications/:id/announcements
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body catalog.AnnouncementInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/announcements [post]
func PostAdminApplicationsIdAnnouncements() {}

// @Summary 公告 GET /announcements/:id
// @Tags 公告
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/announcements/{id} [get]
func GetAdminAnnouncementsId() {}

// @Summary 公告 PATCH /announcements/:id
// @Tags 公告
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body catalog.AnnouncementInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/announcements/{id} [patch]
func PatchAdminAnnouncementsId() {}

// @Summary 公告 DELETE /announcements/:id
// @Tags 公告
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/announcements/{id} [delete]
func DeleteAdminAnnouncementsId() {}

// @Summary 软件 GET /applications/:id/versions
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Param q query string false "关键字（最多128字节）"
// @Param sort_order query string false "asc / desc，默认desc"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "排序字段；允许值见接口契约"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/versions [get]
func GetAdminApplicationsIdVersions() {}

// @Summary 软件 POST /applications/:id/versions
// @Tags 软件
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body catalog.VersionInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/versions [post]
func PostAdminApplicationsIdVersions() {}

// @Summary 版本 GET /versions/:id
// @Tags 版本
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope{data=catalog.VersionInfo}
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/versions/{id} [get]
func GetAdminVersionsId() {}

// @Description disabled独立于withdrawn；禁用后已上报该版本的授权校验返回VERSION_DISABLED及latest_version，旧版本仍可检查更新。
// @Summary 版本 PATCH /versions/:id
// @Tags 版本
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Accept json
// @Param body body catalog.VersionInput true "请求参数"
// @Success 200 {object} Envelope{data=catalog.VersionInfo}
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/versions/{id} [patch]
func PatchAdminVersionsId() {}

// @Summary 版本 DELETE /versions/:id
// @Tags 版本
// @Produce json
// @Security AdminBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/versions/{id} [delete]
func DeleteAdminVersionsId() {}

// @Summary 系统设置 GET /system/settings
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/settings [get]
func GetAdminSystemSettings() {}

// @Summary 系统设置 PATCH /system/settings
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body automation.SettingsInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/settings [patch]
func PatchAdminSystemSettings() {}

// @Summary 系统设置 POST /system/smtp/test
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body SMTPTestRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/smtp/test [post]
func PostAdminSystemSmtpTest() {}

// @Summary 系统设置 GET /system/backups
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/backups [get]
func GetAdminSystemBackups() {}

// @Summary 系统设置 POST /system/backups
// @Description 同步创建一致快照及完整ZIP，路由写期限6分钟。
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/backups [post]
func PostAdminSystemBackups() {}

// @Summary 系统设置 GET /system/backups/:name
// @Description 独立5分钟绝对流式写期限，支持Range，不先将大文件读入内存。
// @Tags 系统设置
// @Security AdminBearer
// @Param name path string true "name"
// @Produce application/zip
// @Success 200 {string} string "下载文件（失败时返回JSON错误）"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/backups/{name} [get]
func GetAdminSystemBackupsName() {}

// @Summary 统计 GET /stats/overview
// @Description counts.suspected_sharing 为本地 IP 库可用时未忽略的共享提示数量；不可用时为0。
// @Description counts.online_instances为活动浮动实例中offline_at为空且lease_expires_at严格晚于as_of的数量；只统计服务端租约，不代表断网中真实运行的数量。
// @Tags 统计
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/stats/overview [get]
func GetAdminStatsOverview() {}

// @Summary 统计 GET /stats/trend
// @Tags 统计
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/stats/trend [get]
func GetAdminStatsTrend() {}

// @Summary 统计 GET /stats/failures
// @Tags 统计
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/stats/failures [get]
func GetAdminStatsFailures() {}

// @Summary 验证日志 GET /verify-logs
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 验证日志
// @Produce json
// @Security AdminBearer
// @Param code query string false "code；规则见接口契约"
// @Param ip query string false "ip；规则见接口契约"
// @Param q query string false "关键字（最多128字节）"
// @Param sort_order query string false "asc / desc，默认desc"
// @Param page query integer false "page；规则见接口契约"
// @Param page_size query integer false "page_size；规则见接口契约"
// @Param sort_by query string false "排序字段；允许值见接口契约"
// @Param success query string false "success；规则见接口契约"
// @Param app_id query string false "app_id；规则见接口契约"
// @Param license_id query string false "license_id；规则见接口契约"
// @Param from query string false "from；规则见接口契约"
// @Param to query string false "to；规则见接口契约"
// @Success 200 {object} VerifyLogResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/verify-logs [get]
func GetAdminVerifyLogs() {}

// @Summary 用户中心 GET /login/options
// @Tags 用户中心
// @Produce json
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/login/options [get]
func GetPortalLoginOptions() {}

// @Summary 用户中心 POST /login/code
// @Tags 用户中心
// @Produce json
// @Accept json
// @Param body body PortalCodeRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/login/code [post]
func PostPortalLoginCode() {}

// @Summary 用户中心 POST /login
// @Tags 用户中心
// @Produce json
// @Accept json
// @Param body body portal.LoginInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/login [post]
func PostPortalLogin() {}

// @Summary 用户中心 GET /license
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/license [get]
func GetPortalLicense() {}

// @Summary 用户中心 GET /activations
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} PortalActivationResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/activations [get]
func GetPortalActivations() {}

// @Summary 用户中心释放实例
// @Description 删除实例记录并写事务审计，不改变会话token或原签名宽限；管理端列表和详情不再显示释放行。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Param id path string true "id"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/activations/{id}/release-seat [post]
func PostPortalActivationsIdUnbind() {}

// @Summary 用户中心 GET /logs
// @Description IP 库未启用时省略 ip_info；启用后按原始 IP 批量去重后本地查询。实例 ip_info 对应 last_ip。用户中心原有 IP 脱敏保持不变，ip_info 不包含原始 IP。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} PortalVerificationLogResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/logs [get]
func GetPortalLogs() {}

// @Summary 用户中心 GET /announcements
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/announcements [get]
func GetPortalAnnouncements() {}

// @Summary 加密客户端统一入口
// @Tags 客户端
// @Description v2 X25519/HKDF/AES-GCM外层；动作、HMAC、nonce和票据位于密文。业务拒绝也是200密文；解密/外层限流统一固定400。完整字节规范见server/internal/apidocs/protocol.md。
// @Description instance：支持instance_session进程接管及release-seat释放浮动容量；INSTANCE_REPLACED明确拒绝但保留缓存，VERSION_DISABLED返回latest_version。
// @Description 显式释放删除浮动实例后，新的instance_session可凭未撤销KEY会话锚点在普通verify中按容量重建；历史接管进程仍拒绝，update.check/payload.unlock不得据此隐式占位。
// @Accept json
// @Produce json
// @Description payload.unlock内层body携带完整payload.json（含config）、ephemeral_public_key及现有授权/激活令牌/实例/challenge字段。严格按授权、席位、信封、版本、维护期的顺序检查；成功data含重封装e/n/c和is_trial，不返回明文内容密钥。信封失败PAYLOAD_INVALID不是授权拒绝，不清授权缓存。细节见接入协议12.6。
// @Param body body GatewayRequest true "v2加密请求"
// @Success 200 {object} GatewayResponse
// @Failure 400 {object} GatewayError
// @Router /api/v1/client/gateway [post]
func PostGateway() {}

type GatewayError struct {
	Error string `json:"error"`
}

// @Summary 分配或改分配授权用户
// @Tags 授权
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path string true "授权ID"
// @Param body body licensing.AssignmentInput true "user_id；null表示未分配库存"
// @Success 200 {object} Envelope
// @Failure 400,401,404,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id} [patch]
func PatchAdminLicensesId() {}

// @Summary 查看是否需要首次初始化（不返回令牌）
// @Tags 初始化
// @Produce json
// @Success 200 {object} Envelope
// @Failure 429,500 {object} Envelope
// @Router /api/v1/admin/status [get]
func SetupStatus() {}

type SetupRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary 使用日志中的一次性令牌设置唯一管理员并直接登录
// @Description 无环境初始密码时启用。令牌常量时间校验，每IP每分钟5次；事务内检查无管理员，完成后永久关闭本次入口。
// @Tags 初始化
// @Accept json
// @Produce json
// @Param request body SetupRequest true "初始化参数（敏感）"
// @Success 200 {object} Envelope
// @Failure 401 {object} Envelope
// @Failure 404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/auth/setup [post]
func SetupComplete() {}

type ConnectionRequest struct {
	URL string `json:"url"`
}

// @Summary 显示软件接入配置串（含密钥，写入审计）
// @Description URL默认使用系统对外地址；未配置时前端传当前origin，可复制前修改。返回authgo1.Base64URL(JSON)，包含url/app_key/app_secret/public_key。禁止记录或公开分发。
// @Tags 软件
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "软件编号"
// @Param request body ConnectionRequest true "对外服务地址"
// @Success 200 {object} Envelope
// @Failure 400 {object} Envelope
// @Failure 401 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/connection [post]
func ApplicationConnection() {}

type EndUserInput = enduser.Input
type PortalUserLogin = portal.UserLoginInput
type UserCodeRequest struct {
	Email string `json:"email"`
}
type UserSwitchRequest struct {
	LicenseID uint64 `json:"license_id"`
}
type UserPasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	Code        string `json:"code"`
}

// @Summary 分页查询用户
// @Tags 用户
// @Produce json
// @Security AdminBearer
// @Param page query int false "页码"
// @Param page_size query int false "每页数量，最多100"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/users [get]
func adminUsersList() {}

// @Summary 创建用户
// @Tags 用户
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body EndUserInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/users [post]
func adminUsersCreate() {}

// @Summary 用户详情
// @Tags 用户
// @Produce json
// @Security AdminBearer
// @Param id path int true "编号"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/users/{id} [get]
func adminUserGet() {}

// @Summary 更新用户（身份凭据变更吊销用户中心会话）
// @Tags 用户
// @Produce json
// @Security AdminBearer
// @Param id path int true "编号"
// @Accept json
// @Param body body EndUserInput true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/users/{id} [patch]
func adminUserUpdate() {}

// @Summary 删除无授权用户
// @Tags 用户
// @Produce json
// @Security AdminBearer
// @Param id path int true "编号"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/users/{id} [delete]
func adminUserDelete() {}

// @Summary 发送用户登录验证码（统一响应，防枚举）
// @Tags 用户中心
// @Produce json
// @Accept json
// @Param body body UserCodeRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/user/login/code [post]
func portalLoginCode() {}

// @Summary 用户邮箱登录
// @Tags 用户中心
// @Produce json
// @Accept json
// @Param body body PortalUserLogin true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/user/login [post]
func portalLogin() {}

// @Summary 查询会话作用域和已选授权
// @Description ip_info_dbip 仅在启用且使用 DB-IP 库时返回 true，用于用户中心页脚署名。不包含路径、错误或管理设置。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} PortalSessionResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/session [get]
func portalSession() {}

// @Summary 首页汇总和用户资料
// @Description 仅用户作用域；online_instances 使用有效浮动租约口径，保留原有汇总字段。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Success 200 {object} UserSummaryResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/user [get]
func portalUserSummary() {}

// @Summary 名下授权分页列表
// @Description 仅用户作用域；按用户 ID 强制过滤。新增在线实例/上限、维护期、最高可用版本和试用转正提示；授权过期或最新版本超出维护期时 renewal_required 为 true。列表不含 Compose、指纹、管理备注、下载地址或令牌。
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Param page query int false "页码"
// @Param page_size query int false "每页数量，最多100"
// @Param status query string false "状态" Enums(active,unused,expired,suspended,revoked)
// @Param app_id query int false "软件编号；仍限定当前用户名下"
// @Success 200 {object} UserLicenseListResponse{data=PortalLicenseList} "操作成功"
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/licenses [get]
func portalLicenseList() {}

// @Summary 切换到本人授权
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Accept json
// @Param body body UserSwitchRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/switch [post]
func portalSwitch() {}

// @Summary 修改用户中心密码并吊销旧会话
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Accept json
// @Param body body UserPasswordRequest true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/password [post]
func portalPasswordChange() {}

// @Summary 释放本人实例席位并删除实例记录，受额度及冷却限制
// @Tags 用户中心
// @Produce json
// @Security PortalBearer
// @Param id path int true "编号"
// @Accept json
// @Param body body map[string]interface{} true "请求参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/user/instances/{id}/release-seat [post]
func portalReleaseSeat() {}

type GatewayRequest struct {
	V int    `json:"v"`
	K string `json:"k"`
	E string `json:"e"`
	N string `json:"n"`
	C string `json:"c"`
}
type GatewayResponse struct {
	N string `json:"n"`
	C string `json:"c"`
}

// @Summary 当前通信配置
// @Tags 故障可用
// @Security AdminBearer
// @Produce json
// @Success 200 {object} Envelope
// @Failure 400,401,404,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/gateway [get]
func gatewayOperation0() {}

// @Summary 更新通信配置
// @Tags 故障可用
// @Security AdminBearer
// @Produce json
// @Accept json
// @Param body body GatewayRotateInput true "参数"
// @Success 200 {object} Envelope
// @Failure 400,401,404,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/gateway/rotate [post]
func gatewayOperation1() {}

type GatewayRotateInput struct {
	OverlapHours int `json:"overlap_hours"`
}

type UpdateSettingsInput = updater.Settings

// @Summary 查看更新同步和并发设置
// @Tags 自动更新
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/updates [get]
func releaseOperation7() {}

// @Summary 设置轮询、资产大小和下载并发
// @Tags 自动更新
// @Produce json
// @Security AdminBearer
// @Accept json
// @Param body body updater.Settings true "参数"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/updates [patch]
func releaseOperation8() {}

// @Summary 当前授权的软件更新
// @Description 有效unused授权无需先激活。配置docker_image时返回仅当前授权软件的Docker拉取命令（保留原始v标签）；未配置镜像时无更新；不提供托管文件下载。
// @Tags 自动更新
// @Produce json
// @Security PortalBearer
// @Param os query string false "文件下载更新需windows/darwin/linux；Docker版本忽略"
// @Param arch query string false "文件下载更新需amd64/arm64；Docker版本忽略"
// @Param current_version query string false "当前semver，留空返回最新"
// @Success 200 {object} Envelope{data=PortalSoftwareUpdate}
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/portal/update [get]
func releaseOperation9() {}

// interface read-only response additions; active_activations counts status=active rows,
// including KEY activations (KEY does not consume a binding quota).
// instance: online_instances counts only live active floating leases with no offline marker.
type LicenseList struct {
	Items []licensing.LicenseInfo `json:"items"`
	Total int64                   `json:"total"`
}
type PortalLicenseSummary struct {
	ID              uint64  `json:"id"`
	Key             string  `json:"key"`
	AppName         string  `json:"app_name"`
	Status          string  `json:"status"`
	ExpiresAt       *string `json:"expires_at"`
	ActiveInstances int64   `json:"active_instances"`
}
type PortalLicenseList struct {
	Items []PortalLicenseSummary `json:"items"`
	Total int64                  `json:"total"`
}

type ActivationList struct {
	Items []licensing.ActivationInfo `json:"items"`
	Total int64                      `json:"total"`
}

// @Summary 管理端接入协议文档
// @Tags 接入文档
// @Security AdminBearer
// @Description 返回唯一协议来源的同步文本副本，text字段为Markdown。
// @Success 200 {object} Envelope{data=ProtocolText}
// @Failure 401 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/integration/protocol [get]
func moduleProtocol() {}

type ProtocolText struct {
	Text string `json:"text"`
}

// @Summary 管理员释放运行实例席位
// @Description 同一事务删除浮动实例及其引用并写instance.release审计；保留独立KEY会话锚点和缓存，程序下次有权心跳可重新竞争。超时未释放的实例仍保留离线行。
// @Tags 实例
// @Security AdminBearer
// @Param id path int true "激活编号"
// @Success 200 {object} Envelope{data=licensing.ActivationInfo}
// @Failure 401,404,409 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/activations/{id}/release-seat [post]
func instanceReleaseSeat() {}

// @Summary Docker接入与部署文档
// @Tags 接入文档
// @Security AdminBearer
// @Success 200 {object} Envelope{data=ProtocolText}
// @Failure 401 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/integration/docker [get]
func instanceDockerDocument() {}

type ApplicationList struct {
	Items []catalog.ApplicationInfo `json:"items"`
	Total int64                     `json:"total"`
}

// @Summary Docker Hub同步状态
// @Description 镜像名取自软件docker_image，空时不同步。仅公开仓库，无凭据。分页完整成功时才撤回已消失的Docker版本。
// @Tags Docker Hub
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=dockerhub.State}
// @Failure 400,401,404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/dockerhub [get]
func DockerHubStatus() {}

// @Summary 测试Docker Hub连接
// @Description 只读取第一页，不写数据库；返回总标签数及首页可接受/已忽略标签数。
// @Tags Docker Hub
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=dockerhub.ConnectionResult}
// @Failure 400,401,404,409,429,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/dockerhub/test [post]
func DockerHubTest() {}

// @Summary 后台同步Docker Hub版本
// @Description 立即返回running状态，通过GET同步状态查询完成结果(last_result/last_error)。后台最长约90秒；同一软件并发返回409，容量2；限流期间返回429。只收录x.y.z或vx.y.z正式版本，不下载镜像。
// @Tags Docker Hub
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=dockerhub.State}
// @Failure 400,401,404,409,429,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/dockerhub/sync [post]
func DockerHubSync() {}

type DockerHubState = dockerhub.State
type DockerHubConnection = dockerhub.ConnectionResult
type DockerHubPortalUpdate = dockerhub.PortalUpdate

type PortalSoftwareUpdate struct {
	dockerhub.PortalUpdate
	DockerImage string `json:"docker_image,omitempty"`
	DockerPull  string `json:"docker_pull,omitempty"`
}

// @Summary 修改授权更新维护期
// @Tags 管理端-授权
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "授权编号"
// @Param body body maintenance.Input true "maintenance_days从现在计算，0或maintenance_until:null表示不限"
// @Success 200 {object} Envelope
// @Failure 400,401,404,409 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/maintenance [post]
func licenseMaintenanceDoc() {}

// @Summary 读取免授权码试用设置
// @Tags 试用
// @Security AdminBearer
// @Produce json
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=trial.Settings}
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/trial [get]
func trialSettingsGet() {}

// @Summary 保存免授权码试用设置
// @Tags 试用
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "软件编号"
// @Param body body trial.Settings true "试用开关和1至365天"
// @Success 200 {object} Envelope{data=trial.Settings}
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/trial [patch]
func trialSettingsUpdate() {}

// @Summary 读取试用申请信息
// @Tags 试用
// @Security AdminBearer
// @Produce json
// @Param id path int true "授权编号"
// @Success 200 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/trial [get]
func trialClaimInfo() {}

// @Summary 将试用转为正式授权
// @Tags 试用
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "授权编号"
// @Param body body trial.ConvertInput true "用户、正式类型和有效期，可选实例数和维护期"
// @Success 200 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/convert [post]
func trialConvert() {}

// @Summary 试用和转正数量
// @Tags 试用
// @Security AdminBearer
// @Produce json
// @Success 200 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/trials/stats [get]
func trialStats() {}

// @Summary 分页查看软件功能模板
// @Tags 功能模板
// @Security AdminBearer
// @Produce json
// @Param id path int true "软件编号"
// @Param page query int false "页码"
// @Param page_size query int false "每页数量，最多100"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/templates [get]
func featureTemplatesList() {}

// @Summary 新建功能模板
// @Tags 功能模板
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "软件编号"
// @Param body body template.Input true "名称、功能项和可空的发放默认值；维护天数0表示不限"
// @Success 200 {object} Envelope{data=template.Info}
// @Failure 400,401,403,404,409 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/templates [post]
func featureTemplatesCreate() {}

// @Summary 修改功能模板（不影响已发放授权）
// @Tags 功能模板
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param id path int true "软件编号"
// @Param template_id path int true "模板编号，必须属于此软件"
// @Param body body template.Input true "只修改提供的字段，默认值可用null清空"
// @Success 200 {object} Envelope{data=template.Info}
// @Failure 400,401,403,404,409 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/templates/{template_id} [patch]
func featureTemplatesUpdate() {}

// @Summary 删除未被试用设置引用的功能模板
// @Tags 功能模板
// @Security AdminBearer
// @Produce json
// @Param id path int true "软件编号"
// @Param template_id path int true "模板编号，必须属于此软件"
// @Success 200 {object} Envelope
// @Failure 401,403,404,409 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/templates/{template_id} [delete]
func featureTemplatesDelete() {}

// @Summary IP 库状态和设置
// @Description 默认关闭且不联网。DB-IP 库每月自动更新，上传库不被自动覆盖。文件位于 AUTHGO_DATA_DIR/ipdb；状态包含来源、数据日期、大小、更新时间、最近错误及 DB-IP 署名。
// @Tags IP 库
// @Security AdminBearer
// @Produce json
// @Success 200 {object} IPInfoResponse
// @Failure 401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/ip-info [get]
func GetIPInfo() {}

// @Summary 启用并下载 DB-IP City 和 ASN 库
// @Description HTTPS 官方月度 mmdb.gz；当月未发布则回退上月或保留旧库，失败不替换。更新超时三分钟，可取消。
// @Tags IP 库
// @Security AdminBearer
// @Produce json
// @Success 200 {object} IPInfoResponse
// @Failure 400,401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/ip-info/enable [post]
func EnableIPInfo() {}

// @Summary 立即更新 IP 库
// @Description 仅更新 DB-IP 来源，不覆盖管理员上传库。两个下载库全部校验成功后原子切换。
// @Tags IP 库
// @Security AdminBearer
// @Produce json
// @Success 200 {object} IPInfoResponse
// @Failure 400,401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/ip-info/update [post]
func UpdateIPInfo() {}

// @Summary 上传 City 或 ASN MMDB
// @Description 支持 multipart 的 file 字段或原始 application/octet-stream。MMDB 上限512 MiB，HTTP请求上限513 MiB，过大返回413；已知长度与chunked相同。multipart完整尾部通过上限验证后才原子切换，失败保留旧库。文件名不参与存储路径，上传写审计日志。
// @Tags IP 库
// @Security AdminBearer
// @Accept multipart/form-data,application/octet-stream
// @Produce json
// @Param kind path string true "库类型" Enums(city,asn)
// @Param file formData file true "未压缩的 MMDB 文件"
// @Success 200 {object} IPInfoResponse
// @Failure 400,401,413,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/ip-info/{kind} [post]
func UploadIPInfo() {}

// @Summary 停用并删除 IP 库
// @Description 删除两个库并停止月更，写审计日志；不影响原有日志和客户端协议。
// @Tags IP 库
// @Security AdminBearer
// @Produce json
// @Success 200 {object} IPInfoResponse
// @Failure 400,401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/ip-info [delete]
func DeleteIPInfo() {}

type PortalActivationList struct {
	Items []portal.ActivationView `json:"items"`
}
type PortalVerificationLogList struct {
	Items []portal.VerificationLog `json:"items"`
}
type AuditLogItem struct {
	ID         uint64                 `json:"id"`
	CreatedAt  time.Time              `json:"created_at"`
	AdminID    *uint64                `json:"admin_id"`
	Operator   string                 `json:"operator"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	IP         string                 `json:"ip"`
	UserAgent  string                 `json:"user_agent"`
	Summary    string                 `json:"summary"`
	StatusCode int                    `json:"status_code"`
	Details    map[string]interface{} `json:"details"`
	IPInfo     *ipinfo.Info           `json:"ip_info,omitempty"`
}
type AuditLogList struct {
	Items    []AuditLogItem `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int64          `json:"total"`
}
type VerifyLogItem struct {
	ID            uint64       `json:"id"`
	CreatedAt     time.Time    `json:"created_at"`
	LicenseKey    string       `json:"license_key"`
	LicenseSource string       `json:"license_source"`
	AppID         *uint64      `json:"app_id"`
	LicenseID     *uint64      `json:"license_id"`
	ActivationID  *uint64      `json:"activation_id"`
	Action        string       `json:"action"`
	Code          string       `json:"code"`
	Success       bool         `json:"success"`
	Reason        string       `json:"reason"`
	IP            string       `json:"ip"`
	Device        string       `json:"device"`
	ClientVersion string       `json:"client_version"`
	DurationMS    int64        `json:"duration_ms"`
	IPInfo        *ipinfo.Info `json:"ip_info,omitempty"`
}
type VerifyLogList struct {
	Items    []VerifyLogItem `json:"items"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
	Total    int64           `json:"total"`
}

// Named envelopes keep each data schema distinct in the OpenAPI 3.1 generator.
type IPInfoResponse struct {
	Envelope
	Data ipinfo.Status `json:"data"`
}
type AuditLogResponse struct {
	Envelope
	Data AuditLogList `json:"data"`
}
type VerifyLogResponse struct {
	Envelope
	Data VerifyLogList `json:"data"`
}
type PortalActivationResponse struct {
	Envelope
	Data PortalActivationList `json:"data"`
}
type PortalVerificationLogResponse struct {
	Envelope
	Data PortalVerificationLogList `json:"data"`
}
type ActivationListResponse struct {
	Envelope
	Data ActivationList `json:"data"`
}
type LicenseDetailResponse struct {
	Envelope
	Data licensing.Detail `json:"data"`
}

type PortalSessionData struct {
	Scope             string `json:"scope"`
	SelectedLicenseID uint64 `json:"selected_license_id"`
	IPInfoDBIP        bool   `json:"ip_info_dbip,omitempty"`
	SupportContact    string `json:"support_contact,omitempty"`
}
type PortalSessionResponse struct {
	Envelope
	Data PortalSessionData `json:"data"`
}

// @Summary 用户待处理事项
// @Description 仅用户作用域；授权码作用域令牌返回401。按紧急程度排序：运行版本禁用、已过期、已暂停、30天内到期、维护期30天内到期、解绑次数耗尽、有新版本。同类按到期时间、授权和实例编号稳定排序。support_contact 为可选纯文本。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param page query int false "页码" minimum(1)
// @Param page_size query int false "每页数量" default(20) minimum(1) maximum(100)
// @Param app_id query int false "软件编号；仅限名下数据"
// @Param license_id query int false "授权编号；仅限名下数据"
// @Success 200 {object} UserAttentionResponse
// @Failure 400,401,500 {object} Envelope
// @Router /api/v1/portal/user/attention [get]
func usercenterUserAttention() {}

// @Summary 名下授权最近验证记录
// @Description 仅用户作用域；授权码作用域令牌返回401。默认每页10条，时间及编号倒序。返回软件名称、脱敏 IP 和可选本地 ip_info，不返回设备指纹、管理备注。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param page query int false "页码" minimum(1)
// @Param page_size query int false "每页数量" default(10) minimum(1) maximum(100)
// @Param app_id query int false "软件编号；仅限名下数据"
// @Param license_id query int false "授权编号；仅限名下数据"
// @Success 200 {object} UserLogListResponse
// @Failure 400,401,500 {object} Envelope
// @Router /api/v1/portal/user/logs [get]
func usercenterUserLogs() {}

// @Summary 名下软件最新版本
// @Description 仅用户作用域；授权码作用域令牌返回401。每个软件一行，仅读取本地已同步数据，不触发联网。保留Docker原始标签；返回最新版本、最高授权版本、维护期及续期标记，不返回下载地址或令牌。available 表示有可运行的授权版本；has_update 表示相对当前运行版本有更新，未知运行版本时可用于首次安装。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param page query int false "页码" minimum(1)
// @Param page_size query int false "每页数量" default(20) minimum(1) maximum(100)
// @Param app_id query int false "软件编号；仅限名下数据"
// @Param license_id query int false "授权编号；仅限名下数据"
// @Success 200 {object} UserUpdateListResponse
// @Failure 400,401,500 {object} Envelope
// @Router /api/v1/portal/user/updates [get]
func usercenterUserUpdates() {}

// @Summary 名下软件公告汇总
// @Description 仅用户作用域；授权码作用域令牌返回401。软件去重后按发布时间和编号倒序分页；排除草稿、未来和已过期公告。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param page query int false "页码" minimum(1)
// @Param page_size query int false "每页数量" default(20) minimum(1) maximum(100)
// @Param app_id query int false "软件编号；仅限名下数据"
// @Param license_id query int false "授权编号；仅限名下数据"
// @Success 200 {object} UserAnnouncementListResponse
// @Failure 400,401,500 {object} Envelope
// @Router /api/v1/portal/user/announcements [get]
func usercenterUserAnnouncements() {}

// @Summary 名下全部实例
// @Description 仅用户作用域；授权码作用域令牌返回401。仅返回当前用户实例；按软件或授权筛选，页大小最多100。在线仅统计有效浮动租约，不返回 activation_token、指纹原文或管理备注。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param page query int false "页码" minimum(1)
// @Param page_size query int false "每页数量" default(20) minimum(1) maximum(100)
// @Param app_id query int false "软件编号；仅限名下数据"
// @Param license_id query int false "授权编号；仅限名下数据"
// @Success 200 {object} UserInstanceListResponse
// @Failure 400,401,500 {object} Envelope
// @Router /api/v1/portal/user/instances [get]
func usercenterUserInstances() {}

// @Summary 用户所属授权详情和部署内容
// @Description 仅用户作用域，使用与/switch相同的服务端归属校验。Compose内包含当前用户自己的授权码，仅详情返回，不进入列表或日志。镜像使用已同步、授权范围及维护期内的原始标签。部署说明来自server/internal/apidocs/docker.md的客户部分，依照镜像内置非root USER和命名缓存卷运行。
// @Tags 用户中心
// @Security PortalBearer
// @Produce json
// @Param id path int true "当前用户名下授权编号"
// @Success 200 {object} UserLicenseDetailResponse
// @Failure 400,401,404,500 {object} Envelope
// @Router /api/v1/portal/licenses/{id} [get]
func usercenterUserLicenseDetail() {}

// @Summary 读取支持联系方式
// @Tags 系统设置
// @Security AdminBearer
// @Produce json
// @Success 200 {object} SupportSettingsResponse
// @Failure 401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/support [get]
func usercenterGetSupport() {}

// @Summary 保存支持联系方式
// @Description 可选纯文本，最多200个Unicode字符，留空清除。保存到现有Setting表，写管理审计。用户中心通过已有/session响应读取，不调用管理接口。
// @Tags 系统设置
// @Security AdminBearer
// @Accept json
// @Produce json
// @Param body body portal.SupportInput true "必须包含support_contact，允许空串"
// @Success 200 {object} SupportSettingsResponse
// @Failure 400,401,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/system/support [patch]
func usercenterPatchSupport() {}

type UserSummary struct {
	ID                uint64     `json:"id"`
	Name              string     `json:"name"`
	Email             string     `json:"email"`
	LicenseCount      int64      `json:"license_count"`
	InstancesTotal    int64      `json:"instances_total"`
	OnlineInstances   int64      `json:"online_instances"`
	NextExpiresAt     *time.Time `json:"next_expires_at"`
	SelectedLicenseID uint64     `json:"selected_license_id"`
}
type UserSummaryResponse struct {
	Envelope
	Data UserSummary `json:"data"`
}
type UserLicenseList struct {
	Items    []portal.UserLicense `json:"items"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	Total    int64                `json:"total"`
}
type UserLicenseListResponse struct {
	Envelope
	Data UserLicenseList `json:"data"`
}
type UserLicenseDetailResponse struct {
	Envelope
	Data portal.UserLicenseDetail `json:"data"`
}
type UserAttentionList struct {
	Items    []portal.Attention `json:"items"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
	Total    int64              `json:"total"`
}
type UserAttentionResponse struct {
	Envelope
	Data UserAttentionList `json:"data"`
}
type UserLogList struct {
	Items    []portal.UserLog `json:"items"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Total    int64            `json:"total"`
}
type UserLogListResponse struct {
	Envelope
	Data UserLogList `json:"data"`
}
type UserAnnouncementList struct {
	Items    []portal.UserAnnouncement `json:"items"`
	Page     int                       `json:"page"`
	PageSize int                       `json:"page_size"`
	Total    int64                     `json:"total"`
}
type UserAnnouncementListResponse struct {
	Envelope
	Data UserAnnouncementList `json:"data"`
}
type UserUpdateList struct {
	Items    []portal.UserUpdate `json:"items"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
	Total    int64               `json:"total"`
}
type UserUpdateListResponse struct {
	Envelope
	Data UserUpdateList `json:"data"`
}
type usercenterUserInstanceList struct {
	Items    []portal.UserInstance `json:"items"`
	Page     int                   `json:"page"`
	PageSize int                   `json:"page_size"`
	Total    int64                 `json:"total"`
}
type UserInstanceListResponse struct {
	Envelope
	Data usercenterUserInstanceList `json:"data"`
}
type SupportSettingsResponse struct {
	Envelope
	Data portal.SupportSettings `json:"data"`
}

// @Summary 查看软件打包公钥和历史（不含私钥）
// @Tags 打包密钥
// @Produce json
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=PayloadKeyList}
// @Failure 401 {object} Envelope
// @Failure 404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/payload-keys [get]
func ListPayloadKeys() {}

type PayloadKeyList struct {
	Items []payloadkey.Info `json:"items"`
}

// @Summary 生成或轮换软件打包密钥（旧私钥保留以解锁已发布版本）
// @Tags 打包密钥
// @Produce json
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=payloadkey.Info}
// @Failure 401 {object} Envelope
// @Failure 404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/payload-keys [post]
func RotatePayloadKey() {}

type SharingResponse struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Data    sharing.View `json:"data"`
}

// @Summary 获取授权共享检测分布
// @Description 最近24小时成功的 activate、verify、heartbeat 按公网IP去重汇总，超过3个国家或5个ASN时提示；不影响授权校验。instance_count和分布count均为去重来源IP数。库未启用时available=false，保留上次汇总。回落清空flagged_at，保留忽略期限。
// @Tags 授权
// @Security AdminBearer
// @Produce json
// @Param id path string true "授权编号"
// @Success 200 {object} SharingResponse
// @Failure 400,401,403,404,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/sharing [get]
func GetAdminLicenseSharing() {}

// @Summary 忽略此次共享提示30天
// @Description 只隐藏提示，不更改授权或客户端校验；到期后重新汇总仍超过阈值才再次显示。操作写入审计日志。
// @Tags 授权
// @Security AdminBearer
// @Produce json
// @Param id path string true "授权编号"
// @Success 200 {object} SharingResponse
// @Failure 400,401,403,404,409,500 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/licenses/{id}/sharing/ignore [post]
func PostAdminLicenseSharingIgnore() {}

// @Summary 读取软件全部新旧打包key_id的软件水印标记（仅管理员）
// @Tags 代码水印
// @Produce json
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Success 200 {object} Envelope{data=WatermarkTagList}
// @Failure 401,404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/watermark-tags [get]
func ListWatermarkTags() {}

type WatermarkTagList struct {
	Items []payloadkey.WatermarkTagInfo `json:"items"`
}
type WatermarkTraceInput struct {
	Watermark string `json:"watermark"`
}

// @Summary 按水印值追查同软件授权/客户/自助试用来源（审计，不上传文件）
// @Description 只接受非零64位小写十六进制watermark字段。文件在浏览器本地处理，接口不接受文件名/文件内容/片段。旧key_id保留追查支持。
// @Tags 代码水印
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param id path int true "软件编号"
// @Param body body WatermarkTraceInput true "仅水印值"
// @Success 200 {object} Envelope{data=payloadkey.WatermarkTrace}
// @Failure 400,401,404 {object} Envelope
// @Failure 429 {object} Envelope
// @Router /api/v1/admin/applications/{id}/watermark-trace [post]
func TraceWatermark() {}

// @Summary 管理员强制标记实例下线
// @Tags 实例
// @Security AdminBearer
// @Param id path int true "实例编号"
// @Success 200 {object} Envelope
// @Failure 401,404,409,429,503 {object} Envelope
// @Router /api/v1/admin/activations/{id}/offline [post]
func contractAdminOffline() {}

// @Summary 获取当前后台地址与实际路由保留名称
// @Tags 系统设置
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 401,429,500 {object} Envelope
// @Router /api/v1/admin/system/admin-path [get]
func adminPathRead() {}

// @Summary 更换后台页面及管理接口地址并撤销全部管理员会话
// @Description 保存后必须在新地址重新登录；仅接受单段小写字母数字和内部连字符，长度1至48，不允许占用已有公开路由前缀。
// @Tags 系统设置
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param body body map[string]string true "path为新后台地址，例如/my-console"
// @Success 200 {object} Envelope
// @Failure 400,401,429,503 {object} Envelope
// @Router /api/v1/admin/system/admin-path [patch]
func adminPathWrite() {}

// @Summary 获取当前管理接口文档
// @Description 仅登录管理员可读；文档中的管理路径使用当前后台地址。
// @Tags 管理接口文档
// @Produce json
// @Security AdminBearer
// @Success 200 {object} Envelope
// @Failure 401,429,500 {object} Envelope
// @Router /api/v1/admin/docs/openapi.json [get]
func adminOpenAPIJSON() {}

// @Summary 下载当前管理接口YAML文档
// @Tags 管理接口文档
// @Produce application/yaml
// @Security AdminBearer
// @Success 200 {string} string
// @Failure 401,429,500 {object} Envelope
// @Router /api/v1/admin/docs/openapi.yaml [get]
func adminOpenAPIYAML() {}
