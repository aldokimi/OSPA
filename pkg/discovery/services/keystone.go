package services

import (
	"context"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/domains"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/services"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

// KeystoneUserDiscoverer discovers keystone/user resources.
type KeystoneUserDiscoverer struct{}

func (d *KeystoneUserDiscoverer) ResourceType() string {
	return "user"
}

func (d *KeystoneUserDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // users are not project-scoped

		pages, err := users.List(client, users.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		userList, err := users.ExtractUsers(pages)
		if err != nil {
			return
		}

		for _, u := range userList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "user",
				ResourceID:   u.ID,
				ProjectID:    u.DefaultProjectID,
				Resource:     u,
			}:
			}
		}
	}()

	return ch, nil
}

// KeystoneRoleDiscoverer discovers keystone/role resources.
type KeystoneRoleDiscoverer struct{}

func (d *KeystoneRoleDiscoverer) ResourceType() string {
	return "role"
}

func (d *KeystoneRoleDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // roles are global, not project-scoped

		pages, err := roles.List(client, roles.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		roleList, err := roles.ExtractRoles(pages)
		if err != nil {
			return
		}

		for _, r := range roleList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "role",
				ResourceID:   r.ID,
				Resource:     r,
			}:
			}
		}
	}()

	return ch, nil
}

// KeystoneProjectDiscoverer discovers keystone/project resources.
type KeystoneProjectDiscoverer struct{}

func (d *KeystoneProjectDiscoverer) ResourceType() string {
	return "project"
}

func (d *KeystoneProjectDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // projects.List already returns every project the caller is authorized to see

		pages, err := projects.List(client, projects.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		projectList, err := projects.ExtractProjects(pages)
		if err != nil {
			return
		}

		for _, p := range projectList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "project",
				ResourceID:   p.ID,
				ProjectID:    p.ID,
				Resource:     p,
			}:
			}
		}
	}()

	return ch, nil
}

// KeystoneDomainDiscoverer discovers keystone/domain resources.
type KeystoneDomainDiscoverer struct{}

func (d *KeystoneDomainDiscoverer) ResourceType() string {
	return "domain"
}

func (d *KeystoneDomainDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // domains are global, not project-scoped

		pages, err := domains.List(client, domains.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		domainList, err := domains.ExtractDomains(pages)
		if err != nil {
			return
		}

		for _, dom := range domainList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "domain",
				ResourceID:   dom.ID,
				Resource:     dom,
			}:
			}
		}
	}()

	return ch, nil
}

// KeystoneGroupDiscoverer discovers keystone/group resources.
type KeystoneGroupDiscoverer struct{}

func (d *KeystoneGroupDiscoverer) ResourceType() string {
	return "group"
}

func (d *KeystoneGroupDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // groups are global, not project-scoped

		pages, err := groups.List(client, groups.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		groupList, err := groups.ExtractGroups(pages)
		if err != nil {
			return
		}

		for _, g := range groupList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "group",
				ResourceID:   g.ID,
				Resource:     g,
			}:
			}
		}
	}()

	return ch, nil
}

// KeystoneServiceDiscoverer discovers keystone/service resources.
type KeystoneServiceDiscoverer struct{}

func (d *KeystoneServiceDiscoverer) ResourceType() string {
	return "service"
}

func (d *KeystoneServiceDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // the service catalog is global, not project-scoped

		pages, err := services.List(client, services.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		serviceList, err := services.ExtractServices(pages)
		if err != nil {
			return
		}

		for _, svc := range serviceList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "keystone",
				ResourceType: "service",
				ResourceID:   svc.ID,
				Resource:     svc,
			}:
			}
		}
	}()

	return ch, nil
}
