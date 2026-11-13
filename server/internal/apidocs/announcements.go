package apidocs

import "authgo/internal/announcements"

type PublicAnnouncementData struct {
	Items []announcements.Item `json:"items"`
}
type PublicAnnouncementResponse struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Data      PublicAnnouncementData `json:"data"`
	Signature any                    `json:"signature"`
}

// @Summary 获取软件已发布且有效的公告（不签名）
// @Description 仅包含有效公告，最多20条、256 KiB。不存在的软件与无公告响应一致。来源IP每分钟最多30次（IPv6按/64），缓存60秒。此接口不签名，可被中间人篡改；需要防篡改时使用SDK的公告方法。
// @Tags 公告
// @Produce json
// @Param app_key query string true "软件标识"
// @Success 200 {object} PublicAnnouncementResponse
// @Failure 429,500 {object} Envelope
// @Router /api/v1/public/announcements [get]
func PublicAnnouncements() {}
