package payloadkey

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strconv"
)

func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	g := r.Group("/api/v1/admin/applications/:id/payload-keys", middleware.Authenticate(identity))
	id := func(c *gin.Context) (uint64, error) {
		n, e := strconv.ParseUint(c.Param("id"), 10, 64)
		if e != nil || n == 0 {
			return 0, apperror.Invalid("软件编号无效")
		}
		return n, nil
	}
	g.GET("", middleware.Action("payload_key.list", "application"), func(c *gin.Context) {
		n, e := id(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		rows, e := s.List(c.Request.Context(), n)
		if e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, gin.H{"items": rows})
	})
	g.POST("", middleware.Action("payload_key.rotate", "application"), func(c *gin.Context) {
		n, e := id(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		k, e := s.Rotate(c.Request.Context(), n)
		if e != nil {
			response.Fail(c, e)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(n, 10))
		response.Success(c, k)
	})
	trace := r.Group("/api/v1/admin/applications/:id", middleware.Authenticate(identity))
	trace.GET("/watermark-tags", middleware.Action("watermark.tags", "application"), func(c *gin.Context) {
		n, e := id(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		tags, e := s.WatermarkTags(c.Request.Context(), n)
		if e != nil {
			response.Fail(c, e)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(n, 10))
		response.Success(c, gin.H{"items": tags})
	})
	trace.POST("/watermark-trace", middleware.Action("watermark.trace", "application"), func(c *gin.Context) {
		n, e := id(c)
		if e != nil {
			response.Fail(c, e)
			return
		}
		var input struct {
			Watermark string `json:"watermark"`
		}
		body, e := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 256))
		if e != nil || strict(body, &input) != nil {
			response.Fail(c, apperror.Invalid("只接受水印值，不接受文件或其他字段"))
			return
		}
		result, e := s.TraceWatermark(c.Request.Context(), n, input.Watermark)
		if e != nil {
			response.Fail(c, e)
			return
		}
		middleware.ResourceID(c, strconv.FormatUint(n, 10))
		response.Success(c, result)
	})

}
