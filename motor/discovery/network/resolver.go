package network

import (
	"context"

	"go.mondoo.com/cnquery/motor/asset"
	"go.mondoo.com/cnquery/motor/discovery/common"
	"go.mondoo.com/cnquery/motor/platform/detector"
	"go.mondoo.com/cnquery/motor/providers"
	network_transport "go.mondoo.com/cnquery/motor/providers/network"
)

type Resolver struct{}

const (
	DiscoveryAll = "all"
)

func (r *Resolver) Name() string {
	return "Network Resolver"
}

func (r *Resolver) AvailableDiscoveryTargets() []string {
	return []string{DiscoveryAll, common.DiscoveryAuto}
}

func (r *Resolver) Resolve(ctx context.Context, root *asset.Asset, conf *providers.Config, cfn common.CredentialFn, sfn common.QuerySecretFn, userIdDetectors ...providers.PlatformIdDetector) ([]*asset.Asset, error) {
	transport, err := network_transport.New(conf)
	if err != nil {
		return nil, err
	}

	detector := detector.New(transport)
	platform, err := detector.Platform()
	if err != nil {
		return nil, err
	}

	platformID, err := transport.Identifier()
	if err != nil {
		return nil, err
	}

	assetObj := &asset.Asset{
		PlatformIds: []string{platformID},
		Platform:    platform,
		Name:        root.Name,
		Connections: []*providers.Config{conf},
		// FIXME: We don't really know at this point if it is online... need to
		// check first
		State: asset.State_STATE_ONLINE,
	}

	if assetObj.Name == "" {
		assetObj.Name = conf.Host
	}

	return []*asset.Asset{assetObj}, nil
}
