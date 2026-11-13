package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

// canonicalJSON marshals Go values, then recursively sorts JSON object keys.
// This is a key-sorted compact JSON contract, NOT RFC 8785/JCS. Number lexemes
// are preserved (including uint64 values); arrays retain their original order.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeJSON(raw)
}
func canonicalizeJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON 必须为有效 UTF-8")
	}
	if err := validateUnicodeEscapes(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readJSON(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("JSON 必须为单个完整值")
	}
	var result bytes.Buffer
	if err := writeJSON(&result, value); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}
func readJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > 100 {
		return nil, errors.New("JSON 嵌套深度超过 100")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("JSON 对象键无效")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, errors.New("JSON 不允许重复对象键")
				}
				value, err := readJSON(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("JSON 对象未结束")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				value, err := readJSON(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("JSON 数组未结束")
			}
			return array, nil
		}
		return nil, errors.New("JSON 分隔符无效")
	}
	return token, nil
}
func writeJSON(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			out.Write(encoded)
			out.WriteByte(':')
			if err := writeJSON(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		out.Write(encoded)
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them
// instead, so malformed input cannot collide with a genuine replacement rune.
func validateUnicodeEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); {
		if raw[i] == '"' {
			inString = !inString
			i++
			continue
		}
		if !inString || raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			return errors.New("JSON 转义不完整")
		}
		if raw[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(raw) {
			return errors.New("JSON Unicode 转义不完整")
		}
		unit, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if err != nil {
			return errors.New("JSON Unicode 转义无效")
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return errors.New("JSON 包含未配对的代理项")
			}
			low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON 包含未配对的代理项")
			}
			i += 12
			continue
		}
		if unit >= 0xdc00 && unit <= 0xdfff {
			return errors.New("JSON 包含未配对的代理项")
		}
		i += 6
	}
	return nil
}
