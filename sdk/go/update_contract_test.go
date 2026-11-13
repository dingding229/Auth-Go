package sdk

import (
	"encoding/json"
	"testing"
)

func TestDockerHubUpdateDTO(t *testing.T) {
	var u Update
	if err := json.Unmarshal([]byte(`{"available":true,"version":"2.0.0","docker_image":"org/app:2.0.0","docker_pull":"docker pull org/app:2.0.0","maintenance_until":null,"latest_entitled_version":"2.0.0","renewal_required":false}`), &u); err != nil || u.DockerImage != "org/app:2.0.0" || u.DockerPull == "" {
		t.Fatal(u, err)
	}
}
