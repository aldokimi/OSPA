package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
)

type ManillaShare struct{}
type ManillaShareSnapshot struct{}
type ManillaShareNetwork struct{}
type ManillaShareServer struct{}

type ManillaShareDiscoverer struct{}
func (d *ManillaShareDiscoverer) ResourceType() string { return "share" }
func (d *ManillaShareDiscoverer) Discover(ctx context.Context, client interface{}, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	close(ch)
	return ch, nil
}

type ManillaShareSnapshotDiscoverer struct{}
func (d *ManillaShareSnapshotDiscoverer) ResourceType() string { return "share_snapshot" }
func (d *ManillaShareSnapshotDiscoverer) Discover(ctx context.Context, client interface{}, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	close(ch)
	return ch, nil
}

type ManillaShareNetworkDiscoverer struct{}
func (d *ManillaShareNetworkDiscoverer) ResourceType() string { return "share_network" }
func (d *ManillaShareNetworkDiscoverer) Discover(ctx context.Context, client interface{}, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	close(ch)
	return ch, nil
}

type ManillaShareServerDiscoverer struct{}
func (d *ManillaShareServerDiscoverer) ResourceType() string { return "share_server" }
func (d *ManillaShareServerDiscoverer) Discover(ctx context.Context, client interface{}, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	close(ch)
	return ch, nil
}
