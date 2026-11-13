package licensing

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"encoding/json"
	"strings"
	"unicode"
)

func parseMap(raw json.RawMessage, defaultValue model.JSONMap) (model.JSONMap, error) {
	if raw == nil {
		return defaultValue, nil
	}
	if len(raw) > 16384 {
		return nil, apperror.Invalid("JSON 对象不得超过 16 KiB")
	}
	canonical, err := cryptoutil.CanonicalizeJSON(raw)
	if err != nil {
		return nil, apperror.Invalid("JSON 对象格式无效或存在重复键")
	}
	var value model.JSONMap
	if err := value.Scan(canonical); err != nil || value == nil {
		return nil, apperror.Invalid("必须为 JSON 对象，不能为 null 或数组")
	}
	if len(value) > 256 {
		return nil, apperror.Invalid("JSON 对象最多 256 个顶层键")
	}
	for key := range value {
		if key == "" || len(key) > 128 || strings.IndexFunc(key, unicode.IsControl) >= 0 {
			return nil, apperror.Invalid("JSON 键长度或字符无效")
		}
	}
	return value, nil
}
