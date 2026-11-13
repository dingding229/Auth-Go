package client

import (
	"authgo/internal/apperror"
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/licensekey"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"authgo/internal/verify"
	"authgo/sdk/wire"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"io"
	"mime"
	"strconv"
	"time"
	"unicode"
)

type Envelope struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data"`
	Signature *string        `json:"signature"`
	TS        int64          `json:"ts"`
	Nonce     string         `json:"nonce"`
}

func (s *Service) reply(c *gin.Context, result outcome, private ed25519.PrivateKey, now time.Time, nonce string) {
	d := code.Describe(result.Code)
	if result.Data == nil {
		result.Data = map[string]any{}
	}
	result.Data["request_nonce"] = nonce
	body := Envelope{Code: result.Code, Message: d.Message, Data: result.Data, TS: now.Unix(), Nonce: nonce}
	if private != nil {
		payload, err := cryptoutil.CanonicalJSON(map[string]any{"code": body.Code, "data": body.Data, "ts": body.TS})
		if err == nil {
			var sig []byte
			sig, err = cryptoutil.Sign(private, payload)
			if err == nil {
				v := base64.StdEncoding.EncodeToString(sig)
				body.Signature = &v
			}
		}
		if err != nil {
			s.log.Error("客户端响应签名失败", "error", err)
			body.Code = code.InternalError
			body.Message = code.Describe(code.InternalError).Message
			body.Data = map[string]any{"request_nonce": nonce}
			body.Signature = nil
		}
	}
	c.Header("Cache-Control", "no-store")
	if session, ok := c.Get("gateway_session"); ok {
		raw, err := json.Marshal(body)
		if err != nil {
			c.Status(500)
			return
		}
		encrypted, err := session.(*wire.Session).EncryptResponse(raw)
		if err != nil {
			c.Status(500)
			return
		}
		c.JSON(200, encrypted)
		return
	}
	c.Data(400, "application/json", []byte(`{"error":"invalid request"}`))
}
func validText(v string, n int) bool {
	if len(v) > n {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func decode(body []byte, in *Input) bool {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(in) != nil {
		return false
	}
	var extra any
	return d.Decode(&extra) == io.EOF && validText(in.Hostname, 128) && validText(in.OS, 64) && len(in.LicenseKey) <= 128 && len(in.ActivationToken) <= 128 && len(in.Device) <= 128 && len(in.Version) <= 128 && len(in.CurrentVersion) <= 128 && validInstanceSession(in.InstanceSession)
}

// handleAction is the authenticated inner pipeline. In particular, syntactic
// license rejection and the IP bucket precede ALL database lookups.
func (s *Service) handleAction(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		now := s.now().UTC()
		nonce := c.GetHeader("X-Nonce")
		if !validNonce(nonce) {
			nonce = ""
		} // Never reflect unbounded/untrusted control text.
		result := denied(code.InternalError)
		var private ed25519.PrivateKey
		row := model.VerifyLog{CreatedAt: now, Action: op, IP: c.ClientIP()}
		authenticated := false
		defer func() {
			row.Code = result.Code
			row.Success = result.Code == code.OK
			row.Reason = code.Describe(result.Code).Message
			if result.MaintenanceUnknown {
				row.Reason = "版本未收录或缺少发布时间，维护期检查已放行"
			}
			row.LicenseID = result.LicenseID
			row.ActivationID = result.ActivationID
			row.DurationMS = time.Since(start).Milliseconds()
			// Auxiliary logging runs only after the outcome has been decided.
			// Never reserve logging capacity before authentication/business work.
			sample := result.MaintenanceUnknown || !authenticated || result.Code == code.RateLimited || result.Code == code.InvalidRequest || result.Code == code.InvalidLicenseKey || result.Code == code.LicenseNotFound || result.Code == code.DeviceInvalid || result.Code == code.VersionNotAllowed
			if op != "release-seat" || result.Code != code.OK {
				s.recordVerifyLog(row, sample)
			}
		}()
		defer func() {
			if recover() != nil {
				s.log.Error("客户端请求处理异常")
				result = denied(code.InternalError)
				s.reply(c, result, private, now, nonce)
			}
		}()

		finish := func(v outcome) { result = v; s.reply(c, result, private, s.now().UTC(), nonce) }
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			finish(denied(code.InvalidRequest))
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, 65537))
		if err != nil || len(body) > 65536 {
			finish(denied(code.InvalidRequest))
			return
		}
		var in Input
		isPost := op == verify.Activate || op == verify.Verify || op == verify.Heartbeat || op == "deactivate" || op == "release-seat" || op == "update.check" || op == "payload.unlock"
		if isPost || op == "trial" {
			typ, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
			if err != nil || typ != "application/json" || !decode(body, &in) {
				finish(denied(code.InvalidRequest))
				return
			}
			if challenge, err := base64.RawURLEncoding.Strict().DecodeString(in.Challenge); err != nil || len(challenge) != 32 {
				finish(denied(code.InvalidRequest))
				return
			}
			if op != "trial" && licensekey.Validate(in.LicenseKey) != nil {
				finish(denied(code.InvalidLicenseKey))
				return
			}

			if r, problem := verify.Normalize(verify.Request{IP: row.IP, Device: in.Device}); problem == "" {
				row.Device = r.Device
			}
			if op != "payload.unlock" && validText(in.Version, 128) {
				row.ClientVersion = in.Version
			}

		} else if len(body) != 0 {
			finish(denied(code.InvalidRequest))
			return
		}
		key := c.GetHeader("X-App-Key")
		if len(key) > 128 || key == "" {
			finish(denied(code.AppNotFound))
			return
		}
		var app model.Application
		err = s.db.WithContext(c.Request.Context()).Where("app_key = ?", key).First(&app).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			finish(denied(code.AppNotFound))
			return
		}
		if err != nil {
			finish(denied(code.InternalError))
			return
		}
		row.AppID = &app.ID
		private, err = s.privateKey(app)
		if err != nil {
			s.log.Error("读取客户端签名密钥失败", "app_id", app.ID)
			private = nil
			finish(denied(code.InternalError))
			return
		}
		if !validTimestamp(c.GetHeader("X-Timestamp"), now) {
			finish(denied(code.TimestampInvalid))
			return
		}
		if nonce == "" {
			finish(denied(code.InvalidRequest))
			return
		}
		secret, err := s.cipher.Decrypt(app.AppSecretEncrypted, aad(app.AppKey, "app_secret"))
		if err != nil {
			finish(denied(code.InternalError))
			return
		}
		if !cryptoutil.VerifyHMACSHA256(secret, SigningInput(op, c.GetHeader("X-Timestamp"), nonce, body), c.GetHeader("X-Signature")) {
			finish(denied(code.SignatureInvalid))
			return
		}
		authenticated = true
		if isPost {
			var license model.License
			e := s.db.WithContext(c.Request.Context()).Select("id").Where("app_id=? AND key=?", app.ID, in.LicenseKey).First(&license).Error
			if errors.Is(e, gorm.ErrRecordNotFound) {
				finish(denied(code.LicenseNotFound))
				return
			}
			if e != nil {
				finish(denied(code.InternalError))
				return
			}
			if op == "payload.unlock" && !s.payloadLimit.allow(strconv.FormatUint(license.ID, 10), now) {
				limited := denied(code.RateLimited)
				limited.LicenseID = &license.ID
				finish(limited)
				return
			}
			if !s.license.allow(cryptoutil.SHA256([]byte(in.LicenseKey)), now) {
				finish(denied(code.RateLimited))
				return
			}
			replay, full := s.nonces.checkAndAdd(app.AppKey+":"+nonce, now)
			if replay {
				finish(denied(code.ReplayDetected))
				return
			}
			if full {
				finish(denied(code.RateLimited))
				return
			}
		}
		if op == "trial" {
			replay, full := s.nonces.checkAndAdd(app.AppKey+":"+nonce, now)
			if replay {
				finish(denied(code.ReplayDetected))
				return
			}
			if full {
				finish(denied(code.RateLimited))
				return
			}
			l, e := s.trials.Acquire(c.Request.Context(), app.ID, row.IP, in.Device)
			if e != nil {
				finish(updateFailure(e))
				return
			}
			result = outcome{Code: code.OK, Data: map[string]any{"license_key": l.Key, "challenge": in.Challenge}, LicenseID: &l.ID}
			finish(result)
			return
		}
		if app.Status != "active" {
			finish(denied(code.AppDisabled))
			return
		}
		if isPost {
			if op == verify.Activate && in.ActivationToken != "" {
				finish(denied(code.InvalidRequest))
				return
			}
			app, err = s.channel.EnsureApplication(c.Request.Context(), app.ID)
			if err != nil {
				finish(denied(code.InternalError))
				return
			}
			if op == "payload.unlock" {
				in.Version = ""
				in.CurrentVersion = ""
				checked := s.processPolicyPayload(c.Request.Context(), app, verify.Verify, row.IP, in, now, true, true)
				row.ClientVersion = checked.PayloadVersion
				finish(checked)
				return
			}
			if op == "update.check" {
				checked := s.processPolicy(c.Request.Context(), app, verify.Verify, row.IP, in, now, true)
				if checked.Code != code.OK {
					finish(checked)
					return
				}
				var data map[string]any
				v, e := s.hub.ForPortal(c.Request.Context(), *checked.LicenseID, in.CurrentVersion)
				if e != nil {
					finish(updateFailure(e))
					return
				}
				raw, _ := json.Marshal(v)
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				decoder.Decode(&data)

				finish(outcome{Code: code.OK, Data: data, LicenseID: checked.LicenseID, ActivationID: checked.ActivationID})
				return
			}
			finish(s.process(c.Request.Context(), app, op, row.IP, in, now))
			return
		}
		switch op {
		case "public-key":
			finish(outcome{Code: code.OK, Data: map[string]any{"public_key": app.PublicKey, "previous_public_key": app.PreviousPublicKey, "algorithm": "Ed25519"}})
		case "announcement":
			v, e := s.announcements(c.Request.Context(), app.ID, now)
			if e != nil {
				finish(denied(code.InternalError))
			} else {
				finish(outcome{Code: code.OK, Data: map[string]any{"items": v}})
			}
		case "version":
			v, e := s.latestVersion(c.Request.Context(), app.ID, now)
			if errors.Is(e, gorm.ErrRecordNotFound) {
				finish(denied(code.VersionNotFound))
			} else if e != nil {
				finish(denied(code.InternalError))
			} else {
				finish(outcome{Code: code.OK, Data: map[string]any{"version": v}})
			}
		default:
			finish(denied(code.InvalidRequest))
		}
	}
}

// Register exposes no plaintext action routes.
func (s *Service) Register(r *gin.Engine) {
	r.POST("/api/v1/client/gateway", s.Gateway)
}

func updateFailure(err error) outcome {
	var safe *apperror.Error
	if errors.As(err, &safe) {
		out := denied(safe.Code)
		var refusal *maintenance.Refusal
		if errors.As(err, &refusal) {
			out.Data["latest_entitled_version"] = refusal.LatestEntitledVersion
			out.Data["maintenance_until"] = refusal.MaintenanceUntil
		}
		return out
	}
	return denied(code.InternalError)
}
