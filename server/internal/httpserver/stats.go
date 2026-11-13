package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/ipinfo"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	"authgo/internal/sharing"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strings"
	"time"
)

// frontend read models: never serialize associated secrets, tokens or arbitrary request bodies.
func registerStats(r *gin.Engine, database *gorm.DB, identity *auth.Service, ips *ipinfo.Service, shares *sharing.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	root.GET("/stats/overview", handle(func(c *gin.Context) (any, error) {
		tx := database.WithContext(c.Request.Context())
		now := time.Now().UTC()
		day := now.Truncate(24 * time.Hour)
		counts := map[string]int64{}
		for _, v := range []struct {
			name  string
			query *gorm.DB
		}{
			{"users_total", tx.Model(&model.EndUser{})}, {"applications_total", tx.Model(&model.Application{})}, {"licenses_total", tx.Model(&model.License{})},
			{"licenses_active", tx.Model(&model.License{}).Where("status='active' AND (expires_at IS NULL OR expires_at>?)", now)},
			{"licenses_expiring", tx.Model(&model.License{}).Where("status IN ? AND expires_at>? AND expires_at<=?", []string{"unused", "active"}, now, now.Add(7*24*time.Hour))},
			{"online_instances", tx.Model(&model.Activation{}).Where("kind='floating' AND status='active' AND offline_at IS NULL AND lease_expires_at>?", now)},
			{"active_bindings", tx.Model(&model.Activation{}).Where("status='active' AND kind<>'key'")},
			{"today_verifications", tx.Model(&model.VerifyLog{}).Where("created_at>=? AND created_at<=?", day, now)},
			{"today_failures", tx.Model(&model.VerifyLog{}).Where("created_at>=? AND created_at<=? AND success=?", day, now, false)},
		} {
			var n int64
			if e := v.query.Count(&n).Error; e != nil {
				return nil, e
			}
			counts[v.name] = n
		}
		suspected, err := shares.Count(c.Request.Context())
		if err != nil {
			return nil, err
		}
		counts["suspected_sharing"] = suspected
		var expiring []model.License
		if e := tx.Where("status IN ? AND expires_at>? AND expires_at<=?", []string{"unused", "active"}, now, now.Add(7*24*time.Hour)).Order("expires_at ASC,id ASC").Limit(10).Preload("Application", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "name") }).Find(&expiring).Error; e != nil {
			return nil, e
		}
		list := []gin.H{}
		for _, l := range expiring {
			list = append(list, gin.H{"id": l.ID, "key": l.Key, "app_id": l.AppID, "app_name": l.Application.Name, "user_id": l.UserID, "expires_at": l.ExpiresAt, "status": l.Status, "type": l.Type})
		}
		out := gin.H{"counts": counts, "expiring": list, "timezone": "UTC", "as_of": now}
		rate := float64(0)
		if counts["today_verifications"] > 0 {
			rate = float64(counts["today_failures"]) / float64(counts["today_verifications"])
		}
		out["today_failure_rate"] = rate
		return out, nil
	}))
	root.GET("/stats/trend", handle(func(c *gin.Context) (any, error) {
		now := time.Now().UTC()
		start := now.Truncate(24*time.Hour).AddDate(0, 0, -29)
		type point struct {
			Day    string `json:"day"`
			Total  int64  `json:"total"`
			Failed int64  `json:"failed"`
		}
		var rows []point
		e := database.WithContext(c.Request.Context()).Model(&model.VerifyLog{}).Select("strftime('%Y-%m-%d',created_at) AS day,COUNT(*) AS total,SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failed").Where("created_at>=? AND created_at<=?", start, now).Group("day").Order("day").Scan(&rows).Error
		out := make([]point, 0, 30)
		byDay := map[string]point{}
		for _, v := range rows {
			byDay[v.Day] = v
		}
		for n := 0; n < 30; n++ {
			day := start.AddDate(0, 0, n).Format("2006-01-02")
			v := byDay[day]
			v.Day = day
			out = append(out, v)
		}
		return gin.H{"items": out, "timezone": "UTC"}, e
	}))
	root.GET("/stats/failures", handle(func(c *gin.Context) (any, error) {
		type item struct {
			Code  string `json:"code"`
			Count int64  `json:"count"`
		}
		rows := []item{}
		now := time.Now().UTC()
		e := database.WithContext(c.Request.Context()).Model(&model.VerifyLog{}).Select("code,COUNT(*) AS count").Where("created_at>=? AND created_at<=? AND success=?", now.Truncate(24*time.Hour).AddDate(0, 0, -29), now, false).Group("code").Order("count DESC,code ASC").Scan(&rows).Error
		return gin.H{"items": rows}, e
	}))
	root.GET("/verify-logs", handle(func(c *gin.Context) (any, error) {
		q, e := response.ParseList(c.Request.URL.Query(), "id", "created_at", "duration_ms", "code")
		if e != nil {
			return nil, e
		}
		query, e := observationQuery(c, database.Model(&model.VerifyLog{}), "verify_logs")
		if e != nil {
			return nil, e
		}
		if value := c.Query("code"); value != "" {
			if len(value) > 128 {
				return nil, apperror.Invalid("错误码过长")
			}
			query = query.Where("code=?", value)
		}
		if c.Query("success") != "" {
			if c.Query("success") != "true" && c.Query("success") != "false" {
				return nil, apperror.Invalid("success 必须为 true 或 false")
			}
			query = query.Where("success=?", c.Query("success") == "true")
		}
		if ip := c.Query("ip"); ip != "" {
			if len(ip) > 128 {
				return nil, apperror.Invalid("IP 过长")
			}
			query = query.Where("ip=?", ip)
		}
		if q.Q != "" {
			p := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q.Q) + "%"
			query = query.Where("(device LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\' OR license_id IN (SELECT id FROM licenses WHERE key LIKE ? ESCAPE '\\'))", p, p, p)
		}
		var n int64
		if e := query.Count(&n).Error; e != nil {
			return nil, e
		}
		var rows []model.VerifyLog
		if e := q.Apply(query).Preload("License", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "key", "source") }).Find(&rows).Error; e != nil {
			return nil, e
		}
		addresses := make([]string, 0, len(rows))
		for _, v := range rows {
			addresses = append(addresses, v.IP)
		}
		locations := ips.LookupBatch(addresses)
		out := []gin.H{}
		for _, v := range rows {
			key := ""
			source := ""
			if v.License != nil {
				key = v.License.Key
				source = v.License.Source
			}
			out = append(out, gin.H{"license_source": source, "license_key": key, "id": v.ID, "created_at": v.CreatedAt, "app_id": v.AppID, "license_id": v.LicenseID, "activation_id": v.ActivationID, "action": v.Action, "code": v.Code, "success": v.Success, "reason": v.Reason, "ip": v.IP, "device": v.Device, "client_version": v.ClientVersion, "duration_ms": v.DurationMS})
			if v := locations[v.IP]; v != nil {
				out[len(out)-1]["ip_info"] = v
			}
		}
		return q.Data(out, n), nil
	}))
}

func observationQuery(c *gin.Context, query *gorm.DB, table string) (*gorm.DB, error) {
	query = query.WithContext(c.Request.Context())
	if id, e := optionalID(c, "user_id"); e != nil {
		return nil, e
	} else if id != nil {
		query = query.Where(table+".license_id IN (SELECT id FROM licenses WHERE user_id=?)", *id)
	}
	for _, key := range []string{"app_id", "license_id"} {
		id, e := optionalID(c, key)
		if e != nil {
			return nil, e
		}
		if id != nil {
			query = query.Where(fmt.Sprintf("%s.%s=?", table, key), *id)
		}
	}
	var from, to *time.Time
	for _, v := range []struct {
		key string
		dst **time.Time
	}{{"from", &from}, {"to", &to}} {
		if raw := c.Query(v.key); raw != "" {
			t, e := time.Parse(time.RFC3339, raw)
			if e != nil {
				return nil, apperror.Invalid("时间必须为 RFC3339")
			}
			t = t.UTC()
			*v.dst = &t
		}
	}
	if from != nil && to != nil && from.After(*to) {
		return nil, apperror.Invalid("开始时间不能晚于结束时间")
	}
	if from != nil {
		query = query.Where(table+".created_at>=?", *from)
	}
	if to != nil {
		query = query.Where(table+".created_at<=?", *to)
	}
	return query, nil
}
