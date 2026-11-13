package catalog

import (
	"context"
	"testing"
)

func TestDockerImageManagement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.app(t, "容器软件")
	if a.DockerImage != "" {
		t.Fatal(a.DockerImage)
	}
	for _, value := range []string{"your-org/your-app", "docker.io/your-org/your-app", ""} {
		a, err := f.s.UpdateApplication(ctx, a.ID, ApplicationInput{DockerImage: &value})
		if err != nil || a.DockerImage != value {
			t.Fatal(a, err)
		}
		got, err := f.s.GetApplication(ctx, a.ID)
		if err != nil || got.DockerImage != value {
			t.Fatal(got, err)
		}
	}
	for _, value := range []string{"https://evil.invalid/image", "user:password/repo", "org/repo:latest", "UPPER/repo", "org/repo\nrun: bad", "org/repo/extra"} {
		if _, err := f.s.UpdateApplication(ctx, a.ID, ApplicationInput{DockerImage: &value}); err == nil {
			t.Fatal("accepted invalid Docker image")
		}
	}
}
