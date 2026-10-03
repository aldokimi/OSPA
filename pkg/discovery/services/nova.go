package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/hypervisors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

// NovaInstanceDiscoverer discovers nova/instance resources.
type NovaInstanceDiscoverer struct{}

func (d *NovaInstanceDiscoverer) ResourceType() string {
	return "instance"
}

func (d *NovaInstanceDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)

		opts := servers.ListOpts{AllTenants: allTenants}
		pages, err := servers.List(client, opts).AllPages()
		if err != nil {
			return
		}

		serverList, err := servers.ExtractServers(pages)
		if err != nil {
			return
		}

		for _, s := range serverList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "nova",
				ResourceType: "instance",
				ResourceID:   s.ID,
				ProjectID:    s.TenantID,
				Resource:     s,
			}:
			}
		}
	}()

	return ch, nil
}

// NovaKeypairDiscoverer discovers nova/keypair resources.
//
// Keypairs are owned by a user, not a project, so allTenants has no effect
// here (this lists the authenticated user's own keypairs).
type NovaKeypairDiscoverer struct{}

func (d *NovaKeypairDiscoverer) ResourceType() string {
	return "keypair"
}

func (d *NovaKeypairDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := keypairs.List(client, keypairs.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		keypairList, err := keypairs.ExtractKeyPairs(pages)
		if err != nil {
			return
		}

		for _, k := range keypairList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "nova",
				ResourceType: "keypair",
				ResourceID:   k.Name,
				Resource:     k,
			}:
			}
		}
	}()

	return ch, nil
}

// NovaFlavorDiscoverer discovers nova/flavor resources.
//
// Flavors are global, not project-scoped, so allTenants has no effect here.
// AllAccess is used so both public and private flavors are discovered.
type NovaFlavorDiscoverer struct{}

func (d *NovaFlavorDiscoverer) ResourceType() string {
	return "flavor"
}

func (d *NovaFlavorDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		opts := flavors.ListOpts{AccessType: flavors.AllAccess}
		pages, err := flavors.ListDetail(client, opts).AllPages()
		if err != nil {
			return
		}

		flavorList, err := flavors.ExtractFlavors(pages)
		if err != nil {
			return
		}

		for _, f := range flavorList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "nova",
				ResourceType: "flavor",
				ResourceID:   f.ID,
				Resource:     f,
			}:
			}
		}
	}()

	return ch, nil
}

// NovaHypervisorDiscoverer discovers nova/hypervisor resources.
//
// Hypervisors are host-level, not project-scoped, so allTenants has no
// effect here.
type NovaHypervisorDiscoverer struct{}

func (d *NovaHypervisorDiscoverer) ResourceType() string {
	return "hypervisor"
}

func (d *NovaHypervisorDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := hypervisors.List(client, nil).AllPages()
		if err != nil {
			return
		}

		hypervisorList, err := hypervisors.ExtractHypervisors(pages)
		if err != nil {
			return
		}

		for _, h := range hypervisorList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "nova",
				ResourceType: "hypervisor",
				ResourceID:   h.ID,
				Resource:     h,
			}:
			}
		}
	}()

	return ch, nil
}
