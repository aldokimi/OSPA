package services

import (
	"context"
	"path"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/orders"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
)

// BarbicanRefID extracts the trailing UUID from a barbican self-referencing
// URL (e.g. SecretRef, ContainerRef, OrderRef). Barbican's list/get
// responses identify resources by full URL rather than a bare ID field, but
// Delete() calls expect just the UUID.
func BarbicanRefID(ref string) string {
	return path.Base(ref)
}

// BarbicanSecretDiscoverer discovers barbican/secret resources.
type BarbicanSecretDiscoverer struct{}

func (d *BarbicanSecretDiscoverer) ResourceType() string {
	return "secret"
}

func (d *BarbicanSecretDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // barbican scopes secrets by the authenticated project; no all-projects list flag in gophercloud's ListOpts

		pages, err := secrets.List(client, secrets.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		secretList, err := secrets.ExtractSecrets(pages)
		if err != nil {
			return
		}

		for _, s := range secretList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "barbican",
				ResourceType: "secret",
				ResourceID:   BarbicanRefID(s.SecretRef),
				Resource:     s,
			}:
			}
		}
	}()

	return ch, nil
}

// BarbicanContainerDiscoverer discovers barbican/container resources.
type BarbicanContainerDiscoverer struct{}

func (d *BarbicanContainerDiscoverer) ResourceType() string {
	return "container"
}

func (d *BarbicanContainerDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := containers.List(client, containers.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		containerList, err := containers.ExtractContainers(pages)
		if err != nil {
			return
		}

		for _, c := range containerList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "barbican",
				ResourceType: "container",
				ResourceID:   BarbicanRefID(c.ContainerRef),
				Resource:     c,
			}:
			}
		}
	}()

	return ch, nil
}

// BarbicanOrderDiscoverer discovers barbican/order resources.
type BarbicanOrderDiscoverer struct{}

func (d *BarbicanOrderDiscoverer) ResourceType() string {
	return "order"
}

func (d *BarbicanOrderDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := orders.List(client, orders.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		orderList, err := orders.ExtractOrders(pages)
		if err != nil {
			return
		}

		for _, o := range orderList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "barbican",
				ResourceType: "order",
				ResourceID:   BarbicanRefID(o.OrderRef),
				Resource:     o,
			}:
			}
		}
	}()

	return ch, nil
}
