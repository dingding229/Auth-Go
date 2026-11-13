package httpserver

import (
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
)

func withID(fn func(*gin.Context, uint64) (any, error)) gin.HandlerFunc {
	return handle(func(c *gin.Context) (any, error) {
		id, err := parseID(c.Param("id"))
		if err != nil {
			return nil, err
		}
		return fn(c, id)
	})
}
func withBody[T any](fn func(*gin.Context, T) (any, error)) gin.HandlerFunc {
	return handle(func(c *gin.Context) (any, error) {
		var in T
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return fn(c, in)
	})
}
func withIDBody[T any](fn func(*gin.Context, uint64, T) (any, error)) gin.HandlerFunc {
	return withID(func(c *gin.Context, id uint64) (any, error) {
		var in T
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return fn(c, id, in)
	})
}
func created(c *gin.Context, id uint64, err error) {
	if err == nil {
		markResource(c, id)
	}
}
