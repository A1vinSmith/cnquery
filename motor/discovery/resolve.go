package discovery

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/motor/asset"
	"go.mondoo.io/mondoo/motor/discovery/aws"
	"go.mondoo.io/mondoo/motor/discovery/azure"
	"go.mondoo.io/mondoo/motor/discovery/container_registry"
	"go.mondoo.io/mondoo/motor/discovery/docker_engine"
	"go.mondoo.io/mondoo/motor/discovery/equinix"
	"go.mondoo.io/mondoo/motor/discovery/gcp"
	"go.mondoo.io/mondoo/motor/discovery/instance"
	"go.mondoo.io/mondoo/motor/discovery/ipmi"
	"go.mondoo.io/mondoo/motor/discovery/k8s"
	"go.mondoo.io/mondoo/motor/discovery/local"
	"go.mondoo.io/mondoo/motor/discovery/mock"
	"go.mondoo.io/mondoo/motor/discovery/ms365"
	"go.mondoo.io/mondoo/motor/discovery/tar"
	"go.mondoo.io/mondoo/motor/discovery/vagrant"
	"go.mondoo.io/mondoo/motor/discovery/vsphere"
	"go.mondoo.io/mondoo/motor/transports"
	"go.mondoo.io/mondoo/stringx"
)

type Resolver interface {
	Name() string
	Resolve(t *transports.TransportConfig) ([]*asset.Asset, error)
	AvailableDiscoveryTargets() []string
}

var resolver map[string]Resolver

func init() {
	resolver = map[string]Resolver{
		transports.SCHEME_LOCAL:              &local.Resolver{},
		transports.SCHEME_WINRM:              &instance.Resolver{},
		transports.SCHEME_SSH:                &instance.Resolver{},
		transports.SCHEME_DOCKER:             &docker_engine.Resolver{},
		transports.SCHEME_DOCKER_IMAGE:       &docker_engine.Resolver{},
		transports.SCHEME_DOCKER_CONTAINER:   &docker_engine.Resolver{},
		transports.SCHEME_TAR:                &tar.Resolver{},
		transports.SCHEME_K8S:                &k8s.Resolver{},
		transports.SCHEME_GCR:                &gcp.GcrResolver{},
		transports.SCHEME_GCP:                &gcp.GcpResolver{},
		transports.SCHEME_CONTAINER_REGISTRY: &container_registry.Resolver{},
		transports.SCHEME_AZURE:              &azure.Resolver{},
		transports.SCHEME_AWS:                &aws.Resolver{},
		transports.SCHEME_VAGRANT:            &vagrant.Resolver{},
		transports.SCHEME_MOCK:               &mock.Resolver{},
		transports.SCHEME_VSPHERE:            &vsphere.Resolver{},
		transports.SCHEME_VSPHERE_VM:         &vsphere.VMGuestResolver{},
		transports.SCHEME_ARISTA:             &instance.Resolver{},
		transports.SCHEME_MS365:              &ms365.Resolver{},
		transports.SCHEME_IPMI:               &ipmi.Resolver{},
		transports.SCHEME_FS:                 &instance.Resolver{},
		transports.SCHEME_EQUINIX:            &equinix.Resolver{},
		transports.SCHEME_GITHUB:             &instance.Resolver{},
	}
}

func ResolveAsset(root *asset.Asset) ([]*asset.Asset, error) {
	resolved := []*asset.Asset{}

	for i := range root.Connections {
		tc := root.Connections[i]

		resolverId := tc.Backend.Scheme()
		r, ok := resolver[resolverId]
		if !ok {
			return nil, errors.New("unsupported backend: " + resolverId)
		}

		log.Debug().Str("resolver", r.Name()).Msg("run resolver")
		// check that all discovery options are supported and show a user warning
		availableTargets := r.AvailableDiscoveryTargets()
		if tc.Discover != nil {
			for i := range tc.Discover.Targets {
				target := tc.Discover.Targets[i]
				if !stringx.Contains(availableTargets, target) {
					log.Warn().Str("resolver", r.Name()).Msgf("resolver does not support discovery target '%s', the following are supported: %s", target, strings.Join(availableTargets, ","))
				}
			}
		}

		// resolve assets
		resolvedAssets, err := r.Resolve(tc)
		if err != nil {
			return nil, err
		}

		for ai := range resolvedAssets {
			assetObj := resolvedAssets[ai]

			// copy over id detector overwrite
			assetObj.IdDetector = root.IdDetector

			// copy over labels for secret metadata fetching
			assetObj.Labels = root.Labels

			// merge platform ids with root object platform ids
			assetObj.PlatformIds = append(assetObj.PlatformIds, root.PlatformIds...)

			resolved = append(resolved, assetObj)
		}
	}
	return resolved, nil
}

type ResolvedAssets struct {
	Assets []*asset.Asset
	Errors map[*asset.Asset]error
}

func ResolveAssets(rootAssets []*asset.Asset) ResolvedAssets {
	resolved := []*asset.Asset{}
	errors := map[*asset.Asset]error{}
	for i := range rootAssets {
		asset := rootAssets[i]

		resolverAssets, err := ResolveAsset(asset)
		if err != nil {
			errors[asset] = err
		}

		resolved = append(resolved, resolverAssets...)
	}

	return ResolvedAssets{
		Assets: resolved,
		Errors: errors,
	}
}
