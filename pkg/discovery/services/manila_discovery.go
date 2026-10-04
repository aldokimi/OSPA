package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
)

// Stub discoverers for scaffolded services. They satisfy discovery.Discoverer
// with empty channels until real API listing is implemented.

func emptyJobs() (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	close(ch)
	return ch, nil
}

// Octavia discoverers live in octavia.go.

// Senlin discoverers
type SenlinClusterDiscoverer struct{}

func (d *SenlinClusterDiscoverer) ResourceType() string { return "cluster" }
func (d *SenlinClusterDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

type SenlinProfileDiscoverer struct{}

func (d *SenlinProfileDiscoverer) ResourceType() string { return "profile" }
func (d *SenlinProfileDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

type SenlinNodeDiscoverer struct{}

func (d *SenlinNodeDiscoverer) ResourceType() string { return "node" }
func (d *SenlinNodeDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

type SenlinPolicyDiscoverer struct{}

func (d *SenlinPolicyDiscoverer) ResourceType() string { return "policy" }
func (d *SenlinPolicyDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

// Trove discoverers live in trove.go.

// Zaqar discoverers
type ZaqarQueueDiscoverer struct{}

func (d *ZaqarQueueDiscoverer) ResourceType() string { return "queue" }
func (d *ZaqarQueueDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

type ZaqarMessageDiscoverer struct{}

func (d *ZaqarMessageDiscoverer) ResourceType() string { return "message" }
func (d *ZaqarMessageDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}

type ZaqarSubscriptionDiscoverer struct{}

func (d *ZaqarSubscriptionDiscoverer) ResourceType() string { return "subscription" }
func (d *ZaqarSubscriptionDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = ctx
	_ = client
	_ = allTenants
	return emptyJobs()
}
