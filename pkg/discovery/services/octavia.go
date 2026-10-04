package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
)

// OctaviaLoadBalancerDiscoverer discovers octavia/loadbalancer resources.
type OctaviaLoadBalancerDiscoverer struct{}

func (d *OctaviaLoadBalancerDiscoverer) ResourceType() string { return "loadbalancer" }

func (d *OctaviaLoadBalancerDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := loadbalancers.List(client, nil).AllPages()
		if err != nil {
			return
		}
		list, err := loadbalancers.ExtractLoadBalancers(pages)
		if err != nil {
			return
		}
		for _, lb := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "octavia",
				ResourceType: "loadbalancer",
				ResourceID:   lb.ID,
				ProjectID:    lb.ProjectID,
				Resource:     lb,
			}:
			}
		}
	}()
	return ch, nil
}

// OctaviaListenerDiscoverer discovers octavia/listener resources.
type OctaviaListenerDiscoverer struct{}

func (d *OctaviaListenerDiscoverer) ResourceType() string { return "listener" }

func (d *OctaviaListenerDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := listeners.List(client, nil).AllPages()
		if err != nil {
			return
		}
		list, err := listeners.ExtractListeners(pages)
		if err != nil {
			return
		}
		for _, l := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "octavia",
				ResourceType: "listener",
				ResourceID:   l.ID,
				ProjectID:    l.ProjectID,
				Resource:     l,
			}:
			}
		}
	}()
	return ch, nil
}

// OctaviaPoolDiscoverer discovers octavia/pool resources.
type OctaviaPoolDiscoverer struct{}

func (d *OctaviaPoolDiscoverer) ResourceType() string { return "pool" }

func (d *OctaviaPoolDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := pools.List(client, nil).AllPages()
		if err != nil {
			return
		}
		list, err := pools.ExtractPools(pages)
		if err != nil {
			return
		}
		for _, p := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "octavia",
				ResourceType: "pool",
				ResourceID:   p.ID,
				ProjectID:    p.ProjectID,
				Resource:     p,
			}:
			}
		}
	}()
	return ch, nil
}

// OctaviaMemberDiscoverer discovers octavia/member resources by walking pools.
type OctaviaMemberDiscoverer struct{}

func (d *OctaviaMemberDiscoverer) ResourceType() string { return "member" }

func (d *OctaviaMemberDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		poolPages, err := pools.List(client, nil).AllPages()
		if err != nil {
			return
		}
		poolList, err := pools.ExtractPools(poolPages)
		if err != nil {
			return
		}
		for _, p := range poolList {
			memberPages, err := pools.ListMembers(client, p.ID, nil).AllPages()
			if err != nil {
				continue
			}
			members, err := pools.ExtractMembers(memberPages)
			if err != nil {
				continue
			}
			for _, m := range members {
				if m.PoolID == "" {
					m.PoolID = p.ID
				}
				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "octavia",
					ResourceType: "member",
					ResourceID:   m.ID,
					ProjectID:    m.ProjectID,
					Resource:     m,
				}:
				}
			}
		}
	}()
	return ch, nil
}

// OctaviaHealthMonitorDiscoverer discovers octavia/healthmonitor resources.
type OctaviaHealthMonitorDiscoverer struct{}

func (d *OctaviaHealthMonitorDiscoverer) ResourceType() string { return "healthmonitor" }

func (d *OctaviaHealthMonitorDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := monitors.List(client, nil).AllPages()
		if err != nil {
			return
		}
		list, err := monitors.ExtractMonitors(pages)
		if err != nil {
			return
		}
		for _, m := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "octavia",
				ResourceType: "healthmonitor",
				ResourceID:   m.ID,
				ProjectID:    m.ProjectID,
				Resource:     m,
			}:
			}
		}
	}()
	return ch, nil
}
