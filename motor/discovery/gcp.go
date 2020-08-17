package discovery

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/apps/mondoo/cmd/options"
	"go.mondoo.io/mondoo/motor/asset"
	"go.mondoo.io/mondoo/motor/discovery/gcp"
	"go.mondoo.io/mondoo/motor/platform"
	"go.mondoo.io/mondoo/motor/transports"
	gcp_transport "go.mondoo.io/mondoo/motor/transports/gcp"
)

type GcpConfig struct {
	User    string
	Project string
}

func ParseGcpInstanceContext(gcpUrl string) GcpConfig {
	var config GcpConfig

	gcpUrl = strings.TrimPrefix(gcpUrl, "gcp://")

	keyValues := strings.Split(gcpUrl, "/")
	for i := 0; i < len(keyValues); {
		if keyValues[i] == "user" {
			if i+1 < len(keyValues) {
				config.User = keyValues[i+1]
			}
		}
		if keyValues[i] == "project" {
			if i+1 < len(keyValues) {
				config.Project = keyValues[i+1]
			}
		}
		i = i + 2
	}

	return config
}

type gcrResolver struct{}

func (k *gcrResolver) Resolve(in *options.VulnOptsAsset, opts *options.VulnOpts) ([]*asset.Asset, error) {
	resolved := []*asset.Asset{}

	repository := strings.TrimPrefix(in.Connection, "gcr://")
	log.Debug().Str("registry", repository).Msg("fetch meta information from gcr registry")
	r := gcp.NewGCRImages()
	assetList, err := r.ListRepository(repository, true)
	if err != nil {
		log.Error().Err(err).Msg("could not fetch k8s images")
		return nil, err
	}

	for i := range assetList {
		log.Debug().Str("name", assetList[i].Name).Str("image", assetList[i].Connections[0].Host+assetList[i].Connections[0].Path).Msg("resolved image")
		resolved = append(resolved, assetList[i])
	}

	return resolved, nil
}

type gcpResolver struct{}

func (k *gcpResolver) Resolve(in *options.VulnOptsAsset, opts *options.VulnOpts) ([]*asset.Asset, error) {
	resolved := []*asset.Asset{}

	r := gcp.NewCompute()

	// parse context from url
	config := ParseGcpInstanceContext(in.Connection)

	// check if we got a project or try to determine it
	if len(config.Project) == 0 {
		// try to determine current project
		projectid, err := gcp_transport.GetCurrentProject()

		if err != nil || len(projectid) == 0 {
			return nil, errors.New("gcp: no project id provided")
		}
		config.Project = projectid
	}

	// add gcp api as asset
	t := &transports.TransportConfig{
		Backend: transports.TransportBackend_CONNECTION_GCP,
		Options: map[string]string{
			// TODO: support organization scanning as well
			"project": config.Project,
		},
	}

	trans, err := gcp_transport.New(t)
	if err != nil {
		return nil, err
	}

	identifier, err := trans.Identifier()
	if err != nil {
		return nil, err
	}

	// detect platform info for the asset
	detector := platform.NewDetector(trans)
	pf, err := detector.Platform()
	if err != nil {
		return nil, err
	}

	resolved = append(resolved, &asset.Asset{
		ReferenceIDs: []string{identifier},
		Name:         "GCP project " + config.Project,
		Platform:     pf,
		Connections:  []*transports.TransportConfig{t}, // pass-in the current config
	})

	// discover compute instances
	if opts.DiscoverInstances {
		// we may want to pass a specific user, otherwise it will fallback to ssh config
		if len(config.User) > 0 {
			r.InstanceSSHUsername = config.User
		}

		assetList, err := r.ListInstancesInProject(config.Project)
		if err != nil {
			return nil, errors.Wrap(err, "could not fetch gcp compute instances")
		}
		log.Debug().Int("instances", len(assetList)).Msg("completed instance search")

		for i := range assetList {
			log.Debug().Str("name", assetList[i].Name).Msg("resolved gcp compute instance")
			resolved = append(resolved, assetList[i])
		}
	}

	return resolved, nil
}
