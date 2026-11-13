package model

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
)

// JSONMap preserves JSON numbers across SQLite roundtrips, unlike unmarshalling
// features into float64 (which silently changes large integer feature values).
type JSONMap map[string]any

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	raw, err := json.Marshal(m)
	return string(raw), err
}
func (m *JSONMap) Scan(value any) error {
	if value == nil {
		*m = nil
		return nil
	}
	var raw []byte
	switch value := value.(type) {
	case string:
		raw = []byte(value)
	case []byte:
		raw = value
	default:
		return errors.New("JSON 数据库字段类型无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON 数据库字段含有额外内容")
	}
	*m = decoded
	return nil
}
