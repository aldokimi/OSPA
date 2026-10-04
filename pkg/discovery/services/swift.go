package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/accounts"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
)

// ObjectWithContainer carries the parent container name alongside an
// objects.Object, since gophercloud's object listing (and Delete call) is
// always scoped to one container and the Object struct alone doesn't carry
// that association. ContainerPublicRead is set when the parent container
// has a world-readable ACL (for composite exposure checks).
type ObjectWithContainer struct {
	objects.Object
	ContainerName       string
	ContainerPublicRead bool
}

// SwiftAccountDiscoverer discovers the swift/account resource.
//
// An account is a singleton per authenticated project - there is no list
// endpoint, just a Get against the account root - so this always yields at
// most one Job.
type SwiftAccountDiscoverer struct{}

func (d *SwiftAccountDiscoverer) ResourceType() string {
	return "account"
}

func (d *SwiftAccountDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job, 1)

	go func() {
		defer close(ch)
		_ = allTenants

		header, err := accounts.Get(client, accounts.GetOpts{}).Extract()
		if err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case ch <- discovery.Job{
			Service:      "swift",
			ResourceType: "account",
			ResourceID:   "account",
			Resource:     *header,
		}:
		}
	}()

	return ch, nil
}

// SwiftContainerDiscoverer discovers swift/container resources.
type SwiftContainerDiscoverer struct{}

func (d *SwiftContainerDiscoverer) ResourceType() string {
	return "container"
}

func (d *SwiftContainerDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // containers are already scoped to the authenticated project

		pages, err := containers.List(client, containers.ListOpts{Full: true}).AllPages()
		if err != nil {
			return
		}

		containerList, err := containers.ExtractInfo(pages)
		if err != nil {
			return
		}

		for _, c := range containerList {
			if ctx.Err() != nil {
				return
			}
			withACL := ContainerWithACL{Container: c}
			if header, err := containers.Get(client, c.Name, containers.GetOpts{}).Extract(); err == nil && header != nil {
				withACL.ReadACL = header.Read
				withACL.WriteACL = header.Write
			}
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "swift",
				ResourceType: "container",
				ResourceID:   c.Name,
				Resource:     withACL,
			}:
			}
		}
	}()

	return ch, nil
}

// SwiftObjectDiscoverer discovers swift/object resources.
//
// Objects are scoped per-container, so discovery lists containers first and
// then lists each container's objects.
type SwiftObjectDiscoverer struct{}

func (d *SwiftObjectDiscoverer) ResourceType() string {
	return "object"
}

func (d *SwiftObjectDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		containerPages, err := containers.List(client, containers.ListOpts{Full: true}).AllPages()
		if err != nil {
			return
		}

		containerList, err := containers.ExtractInfo(containerPages)
		if err != nil {
			return
		}

		for _, c := range containerList {
			if ctx.Err() != nil {
				return
			}

			publicRead := false
			if header, err := containers.Get(client, c.Name, containers.GetOpts{}).Extract(); err == nil && header != nil {
				publicRead = ACLAllowsWorldRead(header.Read)
			}

			objectPages, err := objects.List(client, c.Name, objects.ListOpts{Full: true}).AllPages()
			if err != nil {
				continue
			}

			objectList, err := objects.ExtractInfo(objectPages)
			if err != nil {
				continue
			}

			for _, o := range objectList {
				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "swift",
					ResourceType: "object",
					ResourceID:   c.Name + "/" + o.Name,
					Resource: ObjectWithContainer{
						Object:              o,
						ContainerName:       c.Name,
						ContainerPublicRead: publicRead,
					},
				}:
				}
			}
		}
	}()

	return ch, nil
}
