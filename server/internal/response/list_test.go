package response

import (
	"net/url"
	"testing"
)

func TestListQueryValidation(t *testing.T) {
	defaults, err := ParseList(url.Values{}, "id", "name", "created_at")
	if err != nil || defaults.SortBy != "created_at" || !defaults.Desc || defaults.Size != 20 {
		t.Fatal("list defaults", err)
	}
	q, err := ParseList(url.Values{"q": {"  测试  "}, "sort_by": {"name"}, "sort_order": {"ASC"}, "page": {"2"}, "page_size": {"5"}}, "name")
	if err != nil || q.Q != "测试" || q.Desc || q.Offset() != 5 {
		t.Fatal("list parse", err)
	}
	for _, values := range []url.Values{{"sort_by": {"private_key_encrypted"}}, {"sort_by": {"name; DROP TABLE applications"}}, {"sort_order": {"invalid"}}, {"sort_by": {""}}} {
		if _, err := ParseList(values, "name"); err == nil {
			t.Fatal("unsafe sort accepted")
		}
	}
}
