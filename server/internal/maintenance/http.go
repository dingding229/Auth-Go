package maintenance

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
	"strconv"
	"time"
)

type Service struct {
	db  *gorm.DB
	now func() time.Time
}

func New(db *gorm.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db, now}
}
func (s *Service) Update(ctx context.Context, id uint64, in Input) (*time.Time, error) {
	at, set, err := in.Resolve(s.now())
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, apperror.Invalid("请填写维护天数或维护期到期时间")
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var l model.License
		if e := tx.First(&l, id).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return e
		}
		if l.Status == "revoked" {
			return apperror.New(409, "INVALID_TRANSITION", "已吊销授权不能修改维护期")
		}
		return tx.Model(&l).Update("maintenance_until", at).Error
	})
	return at, err
}
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin/licenses", middleware.Authenticate(identity))
	root.POST("/:id/maintenance", middleware.Action("license.maintenance", "license"), func(c *gin.Context) {
		id, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			response.Fail(c, apperror.Invalid("授权编号无效"))
			return
		}
		var in Input
		if err := response.BindJSON(c, &in); err != nil {
			response.Fail(c, err)
			return
		}
		at, err := s.Update(c.Request.Context(), id, in)
		if err != nil {
			response.Fail(c, err)
			return
		}
		response.Success(c, gin.H{"maintenance_until": at})
	})
}
