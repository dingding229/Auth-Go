package response

import (
	"authgo/internal/apperror"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/url"
	"strings"
)

type ListQuery struct {
	Page
	Q      string
	SortBy string
	Desc   bool
}

func ParseList(values url.Values, sortFields ...string) (ListQuery, error) {
	page, err := ParsePage(values)
	if err != nil {
		return ListQuery{}, err
	}
	query := ListQuery{Page: page, Q: strings.TrimSpace(values.Get("q")), SortBy: "created_at", Desc: true}
	if len(query.Q) > 128 {
		return query, apperror.Invalid("关键字不得超过 128 字节")
	}
	if values.Has("sort_by") {
		query.SortBy = values.Get("sort_by")
		valid := false
		for _, field := range sortFields {
			if query.SortBy == field {
				valid = true
				break
			}
		}
		if !valid {
			return query, apperror.Invalid("排序字段不受支持")
		}
	}
	if values.Has("sort_order") {
		switch strings.ToLower(values.Get("sort_order")) {
		case "asc":
			query.Desc = false
		case "desc":
			query.Desc = true
		default:
			return query, apperror.Invalid("排序方向必须为 asc 或 desc")
		}
	}
	return query, nil
}
func (q ListQuery) Apply(db *gorm.DB) *gorm.DB {
	db = db.Order(clause.OrderByColumn{Column: clause.Column{Table: clause.CurrentTable, Name: q.SortBy}, Desc: q.Desc})
	if q.SortBy != "id" {
		db = db.Order(clause.OrderByColumn{Column: clause.Column{Table: clause.CurrentTable, Name: "id"}, Desc: q.Desc})
	}
	return db.Offset(q.Offset()).Limit(q.Size)
}
