package ipinfo

import (
	"context"
	"errors"
	"net/http"
)

// Only static messages in this package are safe to expose. Never forward upstream
// errors, paths, URLs or a stored arbitrary string to the management response.
type userError string

func (e userError) Error() string { return string(e) }

const (
	errInvalidMMDB        userError = "无效的 MMDB 文件"
	errTypeMismatch       userError = "MMDB 库类型不匹配，请上传对应的 City 或 ASN 库"
	errInvalidMetadata    userError = "MMDB 元数据无效"
	errInvalidContent     userError = "MMDB 内容校验失败"
	errInvalidKind        userError = "库类型必须是 city 或 asn"
	errDatabaseTooLarge   userError = "MMDB 超过 512 MiB 上限"
	errCompressedTooLarge userError = "压缩文件超过 128 MiB 上限"
	errInvalidGzip        userError = "无效或损坏的 gzip 文件"
	errInvalidUpload      userError = "上传格式无效，请上传未压缩的 MMDB 文件"
	errUploadTooLarge     userError = "上传请求超过 513 MiB 上限（MMDB 文件上限为 512 MiB）"
	errDisabled           userError = "请先启用 IP 库"
	errNotPublished       userError = "当月数据库尚未发布"
	errInvalidState       userError = "IP 库状态文件损坏，请重新启用、上传或删除恢复"
	errUnreadableState    userError = "无法读取 IP 库状态，请检查服务端日志或重新上传恢复"
)
const genericError = "IP 库操作失败，请检查网络或服务端日志后重试"
const canceledError = "IP 库操作已取消或超时，现有库已保留"

var userErrors = []userError{errInvalidMMDB, errTypeMismatch, errInvalidMetadata, errInvalidContent, errInvalidKind, errDatabaseTooLarge, errCompressedTooLarge, errInvalidGzip, errInvalidUpload, errUploadTooLarge, errDisabled, errNotPublished, errInvalidState, errUnreadableState}

func safeMessage(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return canceledError
	}
	var size *http.MaxBytesError
	if errors.As(err, &size) {
		return string(errUploadTooLarge)
	}
	var public userError
	if errors.As(err, &public) {
		for _, known := range userErrors {
			if public == known {
				return string(public)
			}
		}
	}
	return genericError
}
func safeStoredMessage(message string) string {
	if message == "" || message == genericError || message == canceledError {
		return message
	}
	for _, known := range userErrors {
		if message == string(known) {
			return message
		}
	}
	return genericError
}
