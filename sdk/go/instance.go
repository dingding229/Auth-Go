package sdk

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

var processIdentity struct {
	replaced sync.Map
	once     sync.Once
	value    string
	err      error
}

// One ephemeral ID for this process, deliberately absent from sessionState/cache.
func processInstanceSession() (string, error) {
	processIdentity.once.Do(func() {
		var b [16]byte
		_, processIdentity.err = rand.Read(b[:])
		processIdentity.value = base64.RawURLEncoding.EncodeToString(b[:])
	})
	return processIdentity.value, processIdentity.err
}
func (c *Client) instance() (string, error) {
	if c.instanceSession != "" {
		return c.instanceSession, nil
	}
	v, e := processInstanceSession()
	if e != nil {
		return "", failure(InternalError, "无法生成进程标识", e)
	}
	c.instanceSession = v
	return v, nil
}

func (c *Client) replacementIdentity(key string) string {
	session := c.instanceSession
	if session == "" {
		var e error
		session, e = processInstanceSession()
		if e != nil {
			return ""
		}
	}
	return sha([]byte(c.cacheIdentity() + "\x00" + key + "\x00" + session))
}
func (c *Client) processReplaced(key string) bool {
	if key == "" {
		return false
	}
	id := c.replacementIdentity(key)
	_, ok := processIdentity.replaced.Load(id)
	return id != "" && ok
}
func (c *Client) rememberReplacement(key string) {
	c.payloadReady = false
	c.clearPayloadKeys()
	c.replacedKey = key
	c.onlineUntil = time.Time{}
	c.offlineTicket = ""
	c.offlineUntil = time.Time{}
	if id := c.replacementIdentity(key); id != "" {
		processIdentity.replaced.Store(id, true)
	}
}
