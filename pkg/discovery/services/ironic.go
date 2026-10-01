package services

import (
	"context"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/drivers"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/ports"
)

// Chassis represents an ironic chassis. Gophercloud v1.14.1 has no
// baremetal/v1/chassis package, so this is populated via raw REST calls
// against the well-documented ironic API instead (GET/DELETE /v1/chassis).
type Chassis struct {
	UUID        string                 `json:"uuid"`
	Description string                 `json:"description"`
	Extra       map[string]interface{} `json:"extra"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type chassisListResponse struct {
	Chassis []Chassis `json:"chassis"`
}

// NodeDiscoverer discovers ironic/node resources.
type IronicNodeDiscoverer struct{}

func (d *IronicNodeDiscoverer) ResourceType() string {
	return "node"
}

func (d *IronicNodeDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // ironic nodes are not project-scoped

		pages, err := nodes.List(client, nodes.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		nodeList, err := nodes.ExtractNodes(pages)
		if err != nil {
			return
		}

		for _, n := range nodeList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "ironic",
				ResourceType: "node",
				ResourceID:   n.UUID,
				Resource:     n,
			}:
			}
		}
	}()

	return ch, nil
}

// IronicPortDiscoverer discovers ironic/port resources.
type IronicPortDiscoverer struct{}

func (d *IronicPortDiscoverer) ResourceType() string {
	return "port"
}

func (d *IronicPortDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := ports.List(client, ports.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		portList, err := ports.ExtractPorts(pages)
		if err != nil {
			return
		}

		for _, p := range portList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "ironic",
				ResourceType: "port",
				ResourceID:   p.UUID,
				Resource:     p,
			}:
			}
		}
	}()

	return ch, nil
}

// IronicDriverDiscoverer discovers ironic/driver resources.
type IronicDriverDiscoverer struct{}

func (d *IronicDriverDiscoverer) ResourceType() string {
	return "driver"
}

func (d *IronicDriverDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // drivers are installed cluster-wide, not project-scoped

		pages, err := drivers.ListDrivers(client, drivers.ListDriversOpts{}).AllPages()
		if err != nil {
			return
		}

		driverList, err := drivers.ExtractDrivers(pages)
		if err != nil {
			return
		}

		for _, dr := range driverList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "ironic",
				ResourceType: "driver",
				ResourceID:   dr.Name,
				Resource:     dr,
			}:
			}
		}
	}()

	return ch, nil
}

// IronicChassisDiscoverer discovers ironic/chassis resources via a raw REST
// call, since gophercloud has no typed package for this legacy, optional
// ironic resource. This performs a single unpaginated GET /v1/chassis
// rather than following link-based pagination.
type IronicChassisDiscoverer struct{}

func (d *IronicChassisDiscoverer) ResourceType() string {
	return "chassis"
}

func (d *IronicChassisDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		var resp chassisListResponse
		url := client.ServiceURL("chassis")
		if _, err := client.Get(url, &resp, nil); err != nil {
			return
		}

		for _, c := range resp.Chassis {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "ironic",
				ResourceType: "chassis",
				ResourceID:   c.UUID,
				Resource:     c,
			}:
			}
		}
	}()

	return ch, nil
}
