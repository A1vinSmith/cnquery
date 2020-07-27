package resolver

import (
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/apps/mondoo/cmd/options"
	"go.mondoo.io/mondoo/motor/asset"
	vsphere_discovery "go.mondoo.io/mondoo/motor/discovery/vsphere"
	"go.mondoo.io/mondoo/motor/platform"
	"go.mondoo.io/mondoo/motor/transports"
	"go.mondoo.io/mondoo/motor/transports/vsphere"
)

type vsphereResolver struct{}

func (v *vsphereResolver) Resolve(in *options.VulnOptsAsset, opts *options.VulnOpts) ([]*asset.Asset, error) {
	resolved := []*asset.Asset{}

	t := &transports.TransportConfig{}
	err := t.ParseFromURI(in.Connection)
	if err != nil {
		err := errors.Wrapf(err, "cannot connect to %s", in.Connection)
		log.Error().Err(err).Msg("invalid asset connection")
	}

	// copy password from opts asset if it was not encoded in url
	if len(t.Password) == 0 && len(in.Password) > 0 {
		t.Password = in.Password
	}

	// we leverage the vpshere transport to establish a connection
	trans, err := vsphere.New(t)
	if err != nil {
		return nil, err
	}

	client := trans.Client()
	discoveryClient := vsphere_discovery.New(client)

	identifier, err := trans.Identifier()
	if err != nil {
		return nil, err
	}

	info := trans.Info()

	// add asset for the api itself
	resolved = append(resolved, &asset.Asset{
		ReferenceIDs: []string{identifier},
		Name:         info.Name,
		// TODO: we have the same thing in the detector (can we leverage the detector here)
		Platform: &platform.Platform{
			Name:    "vmware-vsphere",
			Title:   info.FullName,
			Release: info.Version,
			Kind:    transports.Kind_KIND_API,
			Runtime: platform.RUNTIME_VSPHERE,
		},
		Connections: []*transports.TransportConfig{t}, // pass-in the current config
	})

	// resolve esxi hosts
	hosts, err := discoveryClient.ListEsxiHosts()
	if err != nil {
		return nil, err
	}

	// add transport config for each host
	for i := range hosts {
		host := hosts[i]
		ht := t.Clone()
		// pass-through "vsphere.vmware.com/reference-type" and "vsphere.vmware.com/inventorypath"
		ht.Options = host.Annotations
		host.Connections = append(host.Connections, ht)

		resolved = append(resolved, host)
	}

	// resolve vms
	vms, err := discoveryClient.ListVirtualMachines()
	if err != nil {
		return nil, err
	}

	// add transport config for each vm
	for i := range vms {
		vm := vms[i]
		vt := t.Clone()
		// pass-through "vsphere.vmware.com/reference-type" and "vsphere.vmware.com/inventorypath"
		vt.Options = vm.Annotations
		vm.Connections = append(vm.Connections, vt)
		resolved = append(resolved, vm)
	}

	return resolved, nil
}
