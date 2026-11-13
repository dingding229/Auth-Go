package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestAnnouncementsWithoutActivationOrCache(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	c.FingerprintFunc = func() (string, error) { t.Fatal("news must not collect a device"); return "", nil }
	items, e := c.Announcements(context.Background())
	if e != nil || len(items) != 1 || items[0].Title != "中文公告" {
		t.Fatal(items, e)
	}
	if c.state.Proof != nil || c.state.Token != "" || c.cacheLoaded || c.fingerprint != "" {
		t.Fatal("news changed activation state")
	}
	files, _ := os.ReadDir(c.CacheDir)
	if len(files) != 0 {
		t.Fatal("news wrote cache")
	}
}
func TestAnnouncementsNeverModifiesProofEvenOnRefusal(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	before, _ := json.Marshal(c.state)
	file, _ := os.ReadFile(c.cachePath())
	for _, mode := range []string{"", "bad-signature", "wrong-nonce", "old-ts", "suspended", "redirect"} {
		s.set(mode)
		items, e := c.Announcements(context.Background())
		if mode == "" {
			if e != nil || len(items) != 1 {
				t.Fatal(e)
			}
		} else if e == nil {
			t.Fatal("untrusted announcement accepted", mode)
		}
		after, _ := json.Marshal(c.state)
		disk, _ := os.ReadFile(c.cachePath())
		if !bytes.Equal(before, after) || !bytes.Equal(file, disk) {
			t.Fatal("news changed cached grant", mode)
		}
	}
	s.set("bad-signature")
	if _, e := c.Announcements(context.Background()); !errors.Is(e, ErrResponseSignatureInvalid) {
		t.Fatal(e)
	}
}
