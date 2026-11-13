package apidocs

import "authgo/internal/publishing"

type PublishingCredentialsResponse struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Data    publishing.Credentials `json:"data"`
}
type PublishingConfigResponse struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Data    publishing.Config `json:"data"`
}
type PublishingRuns struct {
	Items []publishing.Run `json:"items"`
}
type PublishingRunsResponse struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Data    PublishingRuns `json:"data"`
}

// @Summary 读取全局发布凭据状态，不返回令牌或密文
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Success 200 {object} PublishingCredentialsResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/publishing [get]
func PublishingCredentialsGet() {}

// @Summary 保存发布凭据；新令牌联网验证，省略保持原值，空字符串清除
// @Tags 自动发布
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param body body publishing.CredentialsInput true "令牌只写，使用主密钥加密保存"
// @Success 200 {object} PublishingCredentialsResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/system/publishing [patch]
func PublishingCredentialsSave() {}

type PublishingVerificationResponse struct {
	Code    string                             `json:"code"`
	Message string                             `json:"message"`
	Data    publishing.CredentialsVerification `json:"data"`
}

// @Summary 验证已保存的 GitHub 与 Docker Hub 凭据
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Success 200 {object} PublishingVerificationResponse
// @Failure 400,401,403,429,500 {object} Envelope
// @Router /api/v1/admin/system/publishing/verify [post]
func PublishingCredentialsVerify() {}

// @Summary 读取软件的 GitHub 仓库、分支与构建选项
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Success 200 {object} PublishingConfigResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing [get]
func PublishingConfigGet() {}

// @Summary 保存软件发布配置，变更后必须重新同步
// @Tags 自动发布
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Param body body publishing.Config true "owner/repo、分支（默认 main）、接入语言、PHP 模式及加密选项"
// @Success 200 {object} PublishingConfigResponse
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing [patch]
func PublishingConfigSave() {}

// @Summary 预览由服务端生成的固定路径发布工作流
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing/workflow [get]
func PublishingWorkflowGet() {}

// @Summary 检查仓库权限、分支及模板目录内的 Dockerfile
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing/test [post]
func PublishingConnectionTest() {}

// @Summary 同步固定工作流、密封加密的两个 Secret 与 AUTHGO_CONFIG Variable
// @Description 只写 .github/workflows/authgo-publish.yml。不会上传业务代码或 Dockerfile。部分成功可再次同步；相同内容不会重复提交工作流。仅访问 api.github.com，外部操作非原子；结果不明确时先检查 GitHub。审计只记录软件、仓库与动作。
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing/sync [post]
func PublishingRepositorySync() {}

// @Summary 触发 GitHub Actions 构建并推送指定版本与 latest
// @Description 同一软件同步或触发操作互斥。工作流必须已在默认分支上；版本为 Docker 标签可用的严格 SemVer，不含前缀 v 或构建元数据。配置改变后须重新同步。超时可能已提交，应先查看运行状态。
// @Tags 自动发布
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Param body body publishing.DispatchInput true "例如 1.0.0 或 1.1.0-rc.1"
// @Success 200 {object} Envelope
// @Failure 400,401,403,404,409,429,500,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing/dispatch [post]
func PublishingWorkflowDispatch() {}

// @Summary 读取目标分支最近五次工作流运行
// @Tags 自动发布
// @Produce json
// @Security AdminBearer
// @Param id path string true "软件编号"
// @Success 200 {object} PublishingRunsResponse
// @Failure 400,401,403,404,409,429,500,502 {object} Envelope
// @Router /api/v1/admin/applications/{id}/publishing/runs [get]
func PublishingRunsGet() {}
