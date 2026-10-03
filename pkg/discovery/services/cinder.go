package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/extensions/backups"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/extensions/volumetenants"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/qos"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/snapshots"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/volumes"
)

// VolumeWithTenant embeds the project/tenant ID, which the base volumes.Volume
// struct omits. See gophercloud's volumetenants package docs.
type VolumeWithTenant struct {
	volumes.Volume
	volumetenants.VolumeTenantExt
}

// CinderVolumeDiscoverer discovers cinder/volume resources.
type CinderVolumeDiscoverer struct{}

func (d *CinderVolumeDiscoverer) ResourceType() string {
	return "volume"
}

func (d *CinderVolumeDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)

		opts := volumes.ListOpts{AllTenants: allTenants}
		pages, err := volumes.List(client, opts).AllPages()
		if err != nil {
			return
		}

		var volumeList []VolumeWithTenant
		if err := volumes.ExtractVolumesInto(pages, &volumeList); err != nil {
			return
		}

		for _, v := range volumeList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "cinder",
				ResourceType: "volume",
				ResourceID:   v.ID,
				ProjectID:    v.TenantID,
				Resource:     v,
			}:
			}
		}
	}()

	return ch, nil
}

// CinderSnapshotDiscoverer discovers cinder/snapshot resources.
type CinderSnapshotDiscoverer struct{}

func (d *CinderSnapshotDiscoverer) ResourceType() string {
	return "snapshot"
}

func (d *CinderSnapshotDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)

		opts := snapshots.ListOpts{AllTenants: allTenants}
		pages, err := snapshots.List(client, opts).AllPages()
		if err != nil {
			return
		}

		snapshotList, err := snapshots.ExtractSnapshots(pages)
		if err != nil {
			return
		}

		for _, s := range snapshotList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "cinder",
				ResourceType: "snapshot",
				ResourceID:   s.ID,
				Resource:     s,
			}:
			}
		}
	}()

	return ch, nil
}

// CinderBackupDiscoverer discovers cinder/backup resources.
type CinderBackupDiscoverer struct{}

func (d *CinderBackupDiscoverer) ResourceType() string {
	return "backup"
}

func (d *CinderBackupDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)

		opts := backups.ListOpts{AllTenants: allTenants}
		pages, err := backups.List(client, opts).AllPages()
		if err != nil {
			return
		}

		backupList, err := backups.ExtractBackups(pages)
		if err != nil {
			return
		}

		for _, b := range backupList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "cinder",
				ResourceType: "backup",
				ResourceID:   b.ID,
				ProjectID:    b.ProjectID,
				Resource:     b,
			}:
			}
		}
	}()

	return ch, nil
}

// CinderQosDiscoverer discovers cinder/qos resources.
//
// QoS specifications are global admin-only objects (no project scoping),
// so allTenants has no effect here.
type CinderQosDiscoverer struct{}

func (d *CinderQosDiscoverer) ResourceType() string {
	return "qos"
}

func (d *CinderQosDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		pages, err := qos.List(client, qos.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		qosList, err := qos.ExtractQoS(pages)
		if err != nil {
			return
		}

		for _, q := range qosList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "cinder",
				ResourceType: "qos",
				ResourceID:   q.ID,
				Resource:     q,
			}:
			}
		}
	}()

	return ch, nil
}
