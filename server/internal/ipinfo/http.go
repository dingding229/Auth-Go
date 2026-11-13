package ipinfo

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

// Register keeps all IP-library management business logic in this package.
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin/system/ip-info", middleware.Authenticate(identity), func(c *gin.Context) {
		// Database transfer deadlines are route-local; normal APIs keep their short deadlines.
		if c.Request.Method == http.MethodPost {
			controller := http.NewResponseController(c.Writer)
			_ = controller.SetReadDeadline(time.Now().Add(3 * time.Minute))
			_ = controller.SetWriteDeadline(time.Now().Add(4 * time.Minute))
		}
	})

	root.GET("", func(c *gin.Context) { response.Success(c, s.Status()) })
	root.POST("/enable", middleware.Action("ipinfo.enable", "ipdb"), s.operation(func(c *gin.Context) error { return s.Enable(c.Request.Context()) }))
	root.POST("/update", middleware.Action("ipinfo.update", "ipdb"), s.operation(func(c *gin.Context) error { return s.Update(c.Request.Context()) }))
	root.POST("/:kind", middleware.Action("ipinfo.upload", "ipdb"), s.operation(func(c *gin.Context) error {
		// Raw application/octet-stream or multipart file. The client filename is never used.
		kind := c.Param("kind")
		if kind != "city" && kind != "asn" {
			return errInvalidKind
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxDatabaseBytes+(1<<20))
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Minute)
		defer cancel()
		if c.ContentType() == "multipart/form-data" {
			reader, err := c.Request.MultipartReader()
			if err != nil {
				return errInvalidUpload
			}
			return s.uploadMultipart(ctx, kind, reader, c.Request.Body)
		}
		return s.Upload(ctx, kind, c.Request.Body)
	}))
	root.DELETE("", middleware.Action("ipinfo.delete", "ipdb"), s.operation(func(c *gin.Context) error { return s.Delete(c.Request.Context()) }))
}

func (s *Service) operation(fn func(*gin.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := fn(c); err != nil {
			var max *http.MaxBytesError
			if errors.As(err, &max) || errors.Is(err, errDatabaseTooLarge) {
				response.Fail(c, apperror.New(http.StatusRequestEntityTooLarge, "INVALID_REQUEST", safeMessage(err)))
			} else {
				response.Fail(c, apperror.Invalid(safeMessage(err)))
			}
			return
		}
		response.Success(c, s.Status())
	}
}

// Stage the file until the entire HTTP body has passed its ceiling. Otherwise
// trailing parts/epilogues could bypass the chunked limit after a valid file and
// a rejected upload could already have replaced the live database.
func (s *Service) uploadMultipart(ctx context.Context, kind string, reader *multipart.Reader, body io.Reader) error {
	s.op.Lock()
	defer s.op.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	staged, err := os.CreateTemp(s.dir, "db-upload-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	found := false
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if part.FormName() == "file" {
			if found {
				return errInvalidUpload
			}
			found = true
			n, err := io.Copy(staged, io.LimitReader(&contextReader{ctx, part}, MaxDatabaseBytes+1))
			if err != nil {
				return err
			}
			if n > MaxDatabaseBytes {
				return errDatabaseTooLarge
			}
		} else {
			if _, err := io.Copy(io.Discard, &contextReader{ctx, part}); err != nil {
				return err
			}
		}
		if err := part.Close(); err != nil {
			return err
		}
	}
	if _, err := io.Copy(io.Discard, &contextReader{ctx, body}); err != nil {
		return err
	}
	if !found {
		return errInvalidUpload
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return s.upload(ctx, kind, staged)
}
