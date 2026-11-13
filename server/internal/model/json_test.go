package model

import (
	"encoding/json"
	"testing"
)

func TestJSONMapExactNumbers(t *testing.T) {
	var m JSONMap
	for _, raw := range []any{`{"quota":18446744073709551615,"flag":true}`, []byte(`{"quota":18446744073709551615,"flag":true}`)} {
		if err := m.Scan(raw); err != nil {
			t.Fatal(err)
		}
		if m["quota"].(json.Number).String() != "18446744073709551615" || m["flag"] != true {
			t.Fatal("number precision lost")
		}
		value, err := m.Value()
		if err != nil || value == nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []any{123, `[]`, `{} {}`, `{`} {
		if err := m.Scan(raw); err == nil {
			t.Fatal("invalid DB JSON accepted")
		}
	}
	if err := m.Scan(nil); err != nil || m != nil {
		t.Fatal("NULL not supported")
	}
	if value, err := m.Value(); err != nil || value != nil {
		t.Fatal("NULL value")
	}
}
