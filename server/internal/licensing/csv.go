package licensing

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/enduser"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var csvColumns = []string{"key", "app_id", "user_name", "user_email", "type", "verify_methods", "match_mode", "max_activations", "features", "validity_rule", "starts_at", "expires_at", "duration_days", "note", "metadata", "status", "batch_id"}

func jsonText(value any) string { raw, _ := json.Marshal(value); return string(raw) }

func timeText(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
func csvProtect(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if strings.HasPrefix(value, "'") || trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) || strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") {
		return "'" + value
	}
	return value
}
func csvUnprotect(value string) string {
	if strings.HasPrefix(value, "''") {
		return value[1:]
	}
	if strings.HasPrefix(value, "'") {
		original := value[1:]
		if csvProtect(original) == value {
			return original
		}
	}
	return value
}

func (s *Service) Export(ctx context.Context, f Filter) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write(csvColumns); err != nil {
		return nil, err
	}
	// Encode inside one bounded read snapshot, but release the SQLite connection
	// before network I/O. Scan one row at a time instead of retaining 10000 JSON maps.
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		users := map[uint64]*model.EndUser{}
		var all []model.EndUser
		if e := tx.Where("id IN (?)", s.sharingFilter(filterQuery(tx, f), f).Select("licenses.user_id").Limit(MaxBatch+1)).Find(&all).Error; e != nil {
			return e
		}
		for i := range all {
			users[all[i].ID] = &all[i]
		}
		rows, err := s.sharingFilter(filterQuery(tx, f), f).Order("id ASC").Limit(MaxBatch + 1).Rows()
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			count++
			if count > MaxBatch {
				return apperror.Invalid("单次 CSV 导出最多 10000 条，请缩小筛选范围或按批次导出")
			}
			var l model.License
			if err := tx.ScanRows(rows, &l); err != nil {
				return err
			}
			if l.UserID != nil {
				l.User = users[*l.UserID]
			}
			if err := writer.Write(csvRecord(l)); err != nil {
				return err
			}
			writer.Flush()
			if err := writer.Error(); err != nil {
				return err
			}
			if buffer.Len() > MaxCSVBytes {
				return apperror.New(413, "CSV_TOO_LARGE", "导出 CSV 超过 16 MiB，请缩小筛选范围")
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

type RowError struct {
	Row     int    `json:"row"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ImportResult struct {
	BatchID         string     `json:"batch_id"`
	Imported        int        `json:"imported"`
	Valid           int        `json:"valid"`
	Failed          int        `json:"failed"`
	Errors          []RowError `json:"errors"`
	ErrorsTruncated bool       `json:"errors_truncated"`
}

func (r *ImportResult) fail(row int, err error) {
	r.Failed++
	safe := &apperror.Error{}
	if !errors.As(err, &safe) {
		safe = apperror.Invalid("该行数据无法处理")
	}
	if len(r.Errors) < 1000 {
		r.Errors = append(r.Errors, RowError{row, safe.Code, safe.Message})
	} else {
		r.ErrorsTruncated = true
	}
}
func csvInput(values map[string]string) (CreateInput, string, error) {
	in := CreateInput{}
	key := values["key"]
	if err := licensekey.Validate(key); err != nil {
		return in, "", apperror.Invalid("授权码格式或校验位无效")
	}
	var err error
	in.AppID, err = strconv.ParseUint(values["app_id"], 10, 63)
	if err != nil || in.AppID == 0 {
		return in, "", apperror.Invalid("app_id 无效")
	}
	for name, target := range map[string]**string{"type": &in.Type, "match_mode": &in.MatchMode, "validity_rule": &in.ValidityRule, "note": &in.Note} {
		if value, ok := values[name]; ok && value != "" {
			copy := value
			*target = &copy
		}
	}
	for name, target := range map[string]**string{"note": &in.Note} {
		if value, ok := values[name]; ok {
			copy := value
			*target = &copy
		}
	}
	for name, target := range map[string]**int{"max_activations": &in.MaxActivations, "duration_days": &in.DurationDays} {
		if value := values[name]; value != "" {
			number, e := strconv.Atoi(value)
			if e != nil {
				return in, "", apperror.Invalid(name + " 必须为整数")
			}
			*target = &number
		}
	}
	for name, target := range map[string]**[]string{"verify_methods": &in.VerifyMethods} {
		if value := values[name]; value != "" {
			var list []string
			if e := json.Unmarshal([]byte(value), &list); e != nil || list == nil {
				return in, "", apperror.Invalid(name + " 必须为 JSON 数组")
			}
			*target = &list
		}
	}
	if value := values["features"]; value != "" {
		in.Features = json.RawMessage(value)
	}
	if value := values["metadata"]; value != "" {
		in.Metadata = json.RawMessage(value)
	}
	for name, target := range map[string]**time.Time{"starts_at": &in.StartsAt, "expires_at": &in.ExpiresAt} {
		if value := values[name]; value != "" {
			at, e := time.Parse(time.RFC3339Nano, value)
			if e != nil {
				return in, "", apperror.Invalid(name + " 必须为 RFC3339 时间")
			}
			*target = &at
		}
	}
	if value := values["status"]; value != "" && value != "unused" {
		return in, "", apperror.Invalid("CSV 仅能导入 unused 新授权，不能导入活动或终态授权")
	}
	// Exported fixed_days rows already contain a resolved expiration timestamp.
	if in.ValidityRule != nil && *in.ValidityRule == "fixed_days" && in.ExpiresAt != nil {
		rule := "fixed_expiry"
		days := 0
		in.ValidityRule = &rule
		in.DurationDays = &days
	}
	return in, key, nil
}
func (s *Service) Import(ctx context.Context, raw []byte) (ImportResult, error) {
	report := ImportResult{Errors: []RowError{}}
	if !utf8.Valid(raw) {
		return report, apperror.Invalid("CSV 必须为 UTF-8 编码")
	}
	if len(raw) > MaxCSVBytes {
		return report, apperror.New(413, "CSV_TOO_LARGE", "CSV 不得超过 16 MiB")
	}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return report, apperror.Invalid("无法读取 CSV 表头")
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}
	allowed := map[string]bool{}
	for _, name := range csvColumns {
		allowed[name] = true
	}
	columns := map[string]bool{}
	for _, name := range header {
		if !allowed[name] || columns[name] {
			return report, apperror.Invalid("CSV 含未知或重复列（不能导入密码或哈希）")
		}
		columns[name] = true
	}
	if !columns["key"] || !columns["app_id"] {
		return report, apperror.Invalid("CSV 必须含 key 和 app_id 列")
	}
	rows := make([]model.License, 0)
	identities := []model.EndUser{}
	seen := map[string]bool{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		record, e := reader.Read()
		if e == io.EOF {
			break
		}
		count++
		if count > MaxBatch {
			return report, apperror.Invalid("CSV 最多 10000 条数据")
		}
		line := count + 1
		if e != nil {
			var parse *csv.ParseError
			if errors.As(e, &parse) {
				line = parse.Line
			}
			report.fail(line, apperror.Invalid("CSV 记录格式无效"))
			break
		}
		if len(record) > 0 {
			line, _ = reader.FieldPos(0)
		}
		if len(record) != len(header) {
			report.fail(line, apperror.Invalid("CSV 字段数量与表头不一致"))
			continue
		}
		values := map[string]string{}
		for i, name := range header {
			values[name] = csvUnprotect(record[i])
		}
		input, key, e := csvInput(values)
		if e != nil {
			report.fail(line, e)
			continue
		}
		if seen[key] {
			report.fail(line, apperror.New(409, "CONFLICT", "CSV 内授权码重复"))
			continue
		}
		seen[key] = true
		var existing int64
		if e := s.db.WithContext(ctx).Model(&model.License{}).Where("key = ?", key).Count(&existing).Error; e != nil {
			return report, e
		}
		if existing > 0 {
			report.fail(line, apperror.New(409, "CONFLICT", "授权码已存在"))
			continue
		}
		l, _, e := s.prepare(ctx, input)
		if e != nil {
			var safe *apperror.Error
			if !errors.As(e, &safe) {
				return report, e
			}
			report.fail(line, e)
			continue
		}
		user := model.EndUser{Status: "active"}
		if strings.TrimSpace(values["user_name"]) != "" || strings.TrimSpace(values["user_email"]) != "" {
			name := values["user_name"]
			if strings.TrimSpace(name) == "" {
				name = strings.ToLower(strings.TrimSpace(values["user_email"]))
			}
			user.Name, user.Email, e = enduser.Normalize(name, values["user_email"])
			if e != nil {
				report.fail(line, e)
				continue
			}
		}
		identities = append(identities, user)
		l.Key = key
		rows = append(rows, l)
		report.Valid++
	}
	if count == 0 {
		return report, apperror.Invalid("CSV 没有数据行")
	}
	if report.Failed > 0 {
		return report, nil
	}
	batch, e := cryptoutil.RandomString(18)
	if e != nil {
		return report, e
	}
	batch = "batch_" + batch
	for i := range rows {
		rows[i].BatchID = batch
	}
	e = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i, u := range identities {
			if u.Name == "" {
				continue
			}
			var existing model.EndUser
			if u.Email != "" {
				if e := tx.Where("email=?", u.Email).Limit(1).Find(&existing).Error; e != nil {
					return e
				}
			}
			if existing.ID == 0 {
				if e := tx.Create(&u).Error; e != nil {
					return e
				}
				existing = u
			}
			id := existing.ID
			rows[i].UserID = &id
		}
		return tx.Omit("User", "Application").CreateInBatches(&rows, 200).Error
	})
	if e != nil {
		return report, writeError(e)
	}
	report.BatchID = batch
	report.Imported = len(rows)
	return report, nil
}

func csvRecord(l model.License) []string {
	user, email := "", ""
	if l.User != nil {
		user = l.User.Name
		email = l.User.Email
	}
	values := map[string]string{"key": l.Key, "app_id": idString(l.AppID), "user_name": user, "user_email": email, "type": l.Type, "verify_methods": jsonText(l.VerifyMethods), "match_mode": l.MatchMode, "max_activations": strconv.Itoa(l.MaxActivations), "features": jsonText(l.Features), "validity_rule": l.ValidityRule, "starts_at": timeText(l.StartsAt), "expires_at": timeText(l.ExpiresAt), "duration_days": strconv.Itoa(l.DurationDays), "note": l.Note, "metadata": jsonText(l.Metadata), "status": l.Status, "batch_id": l.BatchID}
	out := make([]string, len(csvColumns))
	for i, key := range csvColumns {
		out[i] = csvProtect(values[key])
	}
	return out
}
