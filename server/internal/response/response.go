// Package response provides the common management API envelope and strict inputs.
package response

import (
	"authgo/internal/apperror"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
)

func Success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "操作成功", "data": data, "signature": nil})
}

func Fail(c *gin.Context, err error) {
	var safe *apperror.Error
	if !errors.As(err, &safe) {
		slog.Error("管理接口内部错误", "error", err, "route", c.FullPath())
		safe = apperror.New(http.StatusInternalServerError, "INTERNAL_ERROR", "服务器内部错误")
	}
	c.Set("response_code", safe.Code)
	c.AbortWithStatusJSON(safe.Status, gin.H{"code": safe.Code, "message": safe.Message, "data": nil, "signature": nil})
}

func BindJSON(c *gin.Context, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return apperror.Invalid("请求 JSON 格式或字段无效")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return apperror.Invalid("请求只能包含一个 JSON 对象")
	}
	return nil
}

type Page struct {
	Number int `json:"page"`
	Size   int `json:"page_size"`
}

func (p Page) Offset() int { return (p.Number - 1) * p.Size }
func (p Page) Data(items any, total int64) gin.H {
	return gin.H{"items": items, "page": p.Number, "page_size": p.Size, "total": total}
}
func ParsePage(values url.Values) (Page, error) {
	p := Page{1, 20}
	for key, target := range map[string]*int{"page": &p.Number, "page_size": &p.Size} {
		if values.Has(key) {
			n, err := strconv.Atoi(values.Get(key))
			if err != nil || n < 1 {
				return Page{}, apperror.Invalid("分页参数必须为正整数")
			}
			*target = n
		}
	}
	if p.Number > 1_000_000 || p.Size > 100 {
		return Page{}, apperror.Invalid("page 不得超过 1000000，page_size 不得超过 100")
	}
	return p, nil
}

// NotFound is shared by missing pages, assets and API paths. There is no route-
// specific cache marker, redirect, timestamp or authentication challenge.
func NotFound(c *gin.Context) {
	c.Writer.Header()["Date"] = nil // Suppress net/http's per-request Date as well.
	if c.Request.Method == http.MethodHead {
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.Status(http.StatusNotFound)
		c.Writer.WriteHeaderNow()
		c.Abort()
		return
	}
	Fail(c, apperror.New(http.StatusNotFound, "NOT_FOUND", "接口不存在"))
}
