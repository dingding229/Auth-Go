package apidocs

import "authgo/internal/ipinfo"

type IPSyncPlan = ipinfo.SyncPlan

// @Summary 保存 IP 库定时同步计划
// @Description 标准 5 段 cron，按 UTC 执行，默认 0 3 1 * *，两次执行至少间隔 1 小时。仅使用 DB-IP 免费库；开启后会替换上传库。失败保留原库并退避重试，重启沿用持久化下次时间。
// @Tags IP 库
// @Accept json
// @Produce json
// @Security AdminBearer
// @Param body body ipinfo.SyncPlan true "同步开关和 UTC cron 表达式"
// @Success 200 {object} Envelope
// @Failure 400,401,403,409,500 {object} Envelope
// @Router /api/v1/admin/system/ip-info/schedule [patch]
func SaveIPSyncSchedule() {}
