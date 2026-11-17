package template

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"strconv"
)

func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin/applications/:id/templates", middleware.Authenticate(identity))
	ids := func(c *gin.Context) (uint64, uint64, error) {
		a, e := strconv.ParseUint(c.Param("id"), 10, 64)
		if e != nil || a == 0 {
			return 0, 0, apperror.Invalid("软件编号无效")
		}
		var t uint64
		if c.Param("template_id") != "" {
			t, e = strconv.ParseUint(c.Param("template_id"), 10, 64)
			if e != nil || t == 0 {
				return 0, 0, apperror.Invalid("模板编号无效")
			}
		}
		return a, t, nil
	}
	root.GET("", func(c *gin.Context) {
		a, _, e := ids(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		p, e := response.ParsePage(c.Request.URL.Query())
		if e != nil {
			response.Fail(c, e)
			return
		}
		items, total, e := s.List(c.Request.Context(), a, p)
		if e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, p.Data(items, total))
	})
	save := func(c *gin.Context) {
		a, t, e := ids(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		var in Input
		if e = response.BindJSON(c, &in); e != nil {
			response.Fail(c, e)
			return
		}
		result, e := s.Save(c.Request.Context(), a, t, in)
		if e != nil {
			response.Fail(c, e)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(result.ID, 10))
		response.Success(c, result)
	}
	root.POST("", middleware.Action("template.create", "feature_template"), save)
	root.PATCH("/:template_id", middleware.Action("template.update", "feature_template"), save)
	root.GET("/:template_id/counts", func(c *gin.Context) {
		a, t, err := ids(c)
		if err != nil {
			response.Fail(c, err)
			return
		}
		out, err := s.Counts(c.Request.Context(), a, t)
		if err != nil {
			response.Fail(c, err)
			return
		}
		response.Success(c, out)
	})
	root.POST("/:template_id/sync", middleware.Action("template.sync", "feature_template"), func(c *gin.Context) {
		a, t, err := ids(c)
		if err != nil {
			response.Fail(c, err)
			return
		}
		var in SyncInput
		if err = response.BindJSON(c, &in); err != nil {
			response.Fail(c, err)
			return
		}
		out, err := s.Sync(c.Request.Context(), a, t, in)
		if err != nil {
			response.Fail(c, err)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(t, 10))
		c.Set("audit_template_scope", in.Scope)
		c.Set("audit_template_count", out.Count)
		response.Success(c, out)
	})
	root.DELETE("/:template_id", middleware.Action("template.delete", "feature_template"), func(c *gin.Context) {
		a, t, e := ids(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		if e = s.Delete(c.Request.Context(), a, t); e != nil {
			response.Fail(c, e)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(t, 10))
		response.Success(c, gin.H{"id": t})
	})
}
