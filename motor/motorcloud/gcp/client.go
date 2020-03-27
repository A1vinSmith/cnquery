package gcp

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"go.mondoo.io/mondoo/motor/motoros/local"
	"golang.org/x/oauth2/google"
)

func gcpClient(scope ...string) (*http.Client, error) {
	ctx := context.Background()
	return google.DefaultClient(ctx, scope...)
}

// https://github.com/golang/oauth2/issues/241
// shells out to `gcloud config config-helper --format json` to determine
func GetCurrentProject() (string, error) {
	t, err := local.New()
	if err != nil {
		return "", err
	}
	cmd, err := t.RunCommand("gcloud config config-helper --format json")
	if err != nil {
		return "", err
	}

	gcloudconfig, err := ParseGcloudConfig(cmd.Stdout)
	if err != nil {
		return "", errors.Wrap(err, "could not read gcloud config")
	}

	return gcloudconfig.Configuration.Properties.Core.Project, nil
}

func ParseGcloudConfig(r io.Reader) (GCloudConfig, error) {
	var gcloudconfig GCloudConfig

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return gcloudconfig, err
	}

	err = json.Unmarshal(data, &gcloudconfig)
	if err != nil {
		return gcloudconfig, err
	}
	return gcloudconfig, nil
}

type GCloudConfig struct {
	Configuration GCloudConfiguration `json:"configuration"`
}

type GCloudConfiguration struct {
	Properties GCloudProperties `json:"properties"`
}

type GCloudProperties struct {
	Core GCloudCoreProperties `json:"core"`
}

type GCloudCoreProperties struct {
	Project string `json:"project"`
}
