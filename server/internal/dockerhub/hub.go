package dockerhub

import (
	"authgo/internal/apperror"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxBody = 4 << 20
const maxPages = 10

var tagPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

type tag struct {
	Name    string  `json:"name"`
	Pushed  *string `json:"tag_last_pushed"`
	Updated *string `json:"last_updated"`
}
type page struct {
	Count   int64   `json:"count"`
	Next    *string `json:"next"`
	Results []tag   `json:"results"`
}
type release struct {
	Tag       string
	Published time.Time
}
type snapshot struct {
	versions          map[string]release
	present           map[string]string
	ignored, accepted int
	total             int64
	complete          bool
	partialResult     string
}
type hubFailure struct {
	status  int
	message string
	retry   time.Time
}

func (f *hubFailure) Error() string { return f.message }
func (f *hubFailure) public() error {
	code := "INTERNAL_ERROR"
	status := 502
	if f.status == 404 {
		code = "NOT_FOUND"
		status = 404
	}
	if f.status == 429 {
		code = "RATE_LIMITED"
		status = 429
	}
	return apperror.New(status, code, f.message)
}
func retryTime(h http.Header, now time.Time) time.Time {
	var latest time.Time
	for _, key := range []string{"Retry-After", "X-Retry-After", "X-RateLimit-Reset"} {
		raw := strings.TrimSpace(h.Get(key))
		var at time.Time
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n >= 0 {
			if key == "X-RateLimit-Reset" || n >= 1_000_000_000 {
				at = time.Unix(n, 0)
			} else {
				at = now.Add(time.Duration(n) * time.Second)
			}
		} else if v, err := http.ParseTime(raw); err == nil {
			at = v
		}
		if at.After(latest) {
			latest = at
		}
	}
	if !latest.After(now) {
		latest = now.Add(time.Minute)
	}
	return latest.UTC()
}
func accepted(t tag) (string, time.Time, bool) {
	name := strings.TrimPrefix(t.Name, "v")
	if !tagPattern.MatchString(t.Name) {
		return "", time.Time{}, false
	}
	v, err := semver.StrictNewVersion(name)
	if err != nil || v.Prerelease() != "" || v.Metadata() != "" {
		return "", time.Time{}, false
	}
	raw := t.Pushed
	if raw == nil || *raw == "" {
		raw = t.Updated
	}
	if raw != nil {
		at, err := time.Parse(time.RFC3339Nano, *raw)
		if err == nil && !at.IsZero() {
			return name, at.UTC(), true
		}
	}

	return "", time.Time{}, false
}
func (s *Service) read(ctx context.Context, image string, firstOnly bool) (snapshot, *hubFailure) {
	out := snapshot{versions: map[string]release{}, present: map[string]string{}}
	parts := strings.Split(image, "/")
	for n := 1; n <= maxPages; n++ {
		path := fmt.Sprintf("%s/v2/namespaces/%s/repositories/%s/tags?page=%d&page_size=100", s.api, url.PathEscape(parts[0]), url.PathEscape(parts[1]), n)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return out, &hubFailure{message: "Docker Hub请求失败，请稍后重试"}
		}
		req.Header.Set("Accept", "application/json")
		res, err := s.http.Do(req)
		if err != nil {
			return out, &hubFailure{message: "无法连接Docker Hub或请求超时，请稍后重试"}
		}
		if res.StatusCode != 200 {
			if res.StatusCode == http.StatusForbidden && n > 1 {
				res.Body.Close()
				out.partialResult = "Docker Hub限制了后续分页，只收录已读取的标签，未撤回旧版本"
				return out, nil
			}
			f := &hubFailure{status: res.StatusCode, message: "Docker Hub服务暂时不可用，请稍后重试"}
			if res.StatusCode == http.StatusForbidden {
				f.message = "Docker Hub拒绝访问，请确认仓库是公开仓库"
			}
			if res.StatusCode == 404 {
				f.message = "仓库不存在或不是公开仓库"
			}
			if res.StatusCode == 429 {
				f.message = "Docker Hub请求过于频繁，请等待重试时间后再同步"
				f.retry = retryTime(res.Header, s.now())
			}
			res.Body.Close()
			return out, f
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
		res.Body.Close()
		if err != nil || len(raw) > maxBody {
			return out, &hubFailure{message: "Docker Hub响应不完整或过大，请稍后重试"}
		}
		var p page
		if err := json.Unmarshal(raw, &p); err != nil || p.Count < 0 || p.Results == nil || len(p.Results) > 100 {
			return out, &hubFailure{message: "Docker Hub响应格式无效，请稍后重试"}
		}
		if n == 1 {
			out.total = p.Count
		}
		for _, t := range p.Results {
			candidate := strings.TrimPrefix(t.Name, "v")
			if tagPattern.MatchString(t.Name) {
				if _, err := semver.StrictNewVersion(candidate); err == nil {
					if _, exists := out.present[candidate]; !exists || candidate == t.Name {
						out.present[candidate] = t.Name
					}
				}
			}
			name, at, ok := accepted(t)
			if !ok {
				out.ignored++
				continue
			}
			out.accepted++
			old, exists := out.versions[name]
			if !exists {
				out.versions[name] = release{t.Name, at}
			} else {
				if at.Before(old.Published) {
					old.Published = at
				}
				if t.Name == name {
					old.Tag = t.Name
				}
				out.versions[name] = old
			}
		}
		// The 'next' URL is only a continuation flag. Never use it as a destination.
		if p.Next == nil || *p.Next == "" {
			out.complete = n < maxPages
			return out, nil
		}
		if firstOnly {
			return out, nil
		}
	}
	out.partialResult = "标签超过1000个，只收录最新的1000个，未撤回旧版本"
	return out, nil
}
