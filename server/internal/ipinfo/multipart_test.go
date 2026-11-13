package ipinfo

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"os"
	"strings"
	"sync"
	"testing"
)

type multipartGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (g *multipartGate) Read([]byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return 0, io.EOF
}
func TestMultipartStagingSerializesWithOtherFileOperations(t *testing.T) {
	s := testService(t)
	raw, err := os.ReadFile("testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	gate := &multipartGate{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	prefix := "--authgo-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"city.mmdb\"\r\n\r\n"
	body := io.MultiReader(strings.NewReader(prefix), bytes.NewReader(raw), strings.NewReader("\r\n--authgo-test--\r\n"), gate)
	result := make(chan error, 1)
	go func() {
		result <- s.uploadMultipart(context.Background(), "city", multipart.NewReader(body, "authgo-test"), body)
	}()
	<-gate.entered
	// Delete/update must not overtake an already staging upload. This was the
	// serialization guarantee of the original raw Upload path as well.
	if s.op.TryLock() {
		s.op.Unlock()
		t.Fatal("multipart staging did not hold the operation lock")
	}
	release()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if s.Status().City == nil {
		t.Fatal("upload not committed")
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "db-upload-") {
			t.Fatal("staging file leaked")
		}
	}
}
