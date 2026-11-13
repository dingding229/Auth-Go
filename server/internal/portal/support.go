package portal

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
	"unicode"
	"unicode/utf8"
)

const supportSettingKey = "portal.support_contact"

type SupportSettings struct {
	SupportContact string `json:"support_contact" maxLength:"200"`
}

type SupportInput struct {
	SupportContact *string `json:"support_contact" binding:"required" maxLength:"200"`
}

func supportContact(ctx context.Context, db *gorm.DB) (string, error) {
	var setting model.Setting
	err := db.WithContext(ctx).Where("key=?", supportSettingKey).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	return setting.Value, err
}

// RegisterSupport keeps setting persistence and validation out of httpserver.
func RegisterSupport(r *gin.Engine, db *gorm.DB, identity *auth.Service) {
	root := r.Group("/api/v1/admin/system/support", middleware.Authenticate(identity))
	root.GET("", func(c *gin.Context) {
		v, e := supportContact(c.Request.Context(), db)
		if e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, SupportSettings{v})
	})
	root.PATCH("", middleware.Action("system.support.update", "system"), func(c *gin.Context) {
		var in SupportInput
		if e := response.BindJSON(c, &in); e != nil {
			response.Fail(c, e)
			return
		}
		if in.SupportContact == nil || !utf8.ValidString(*in.SupportContact) || utf8.RuneCountInString(*in.SupportContact) > 200 {
			response.Fail(c, apperror.Invalid("支持联系方式必须是最多 200 字的纯文本，可留空"))
			return
		}
		for _, r := range *in.SupportContact {
			if unicode.IsControl(r) && r != '\n' && r != '\t' {
				response.Fail(c, apperror.Invalid("支持联系方式不能包含控制字符"))
				return
			}
		}
		row := model.Setting{Key: supportSettingKey, Value: *in.SupportContact, UpdatedAt: time.Now().UTC()}
		if e := db.WithContext(c.Request.Context()).Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error; e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, SupportSettings{row.Value})
	})
}
