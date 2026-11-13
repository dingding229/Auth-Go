// Package apperror defines safe, stable errors exposed by HTTP APIs.
package apperror

import "net/http"

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string                    { return e.Code + ": " + e.Message }
func New(status int, code, message string) *Error { return &Error{status, code, message} }
func Invalid(message string) *Error               { return New(http.StatusBadRequest, "INVALID_REQUEST", message) }
func Unauthorized() *Error {
	return New(http.StatusUnauthorized, "UNAUTHORIZED", "登录凭据无效或已过期")
}

func NotFound() *Error               { return New(http.StatusNotFound, "NOT_FOUND", "资源不存在") }
func Conflict(message string) *Error { return New(http.StatusConflict, "CONFLICT", message) }
