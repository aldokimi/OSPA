//go:build e2e

package keystone

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/domains"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/services"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

const testPrefix = "ospa-e2e-"

func CreateUser(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%suser-%d", testPrefix, time.Now().UnixNano())
	enabled := true
	u, err := users.Create(client, users.CreateOpts{
		Name:        name,
		Description: "OSPA e2e test user",
		Enabled:     &enabled,
		Password:    fmt.Sprintf("OspaE2E-%d!", time.Now().UnixNano()),
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	t.Logf("Created test user: %s (%s)", u.Name, u.ID)
	return u.ID, func() {
		t.Logf("Cleaning up test user: %s", u.ID)
		if err := users.Delete(client, u.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete user %s: %v", u.ID, err)
		}
	}
}

func CreateProject(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%sproject-%d", testPrefix, time.Now().UnixNano())
	p, err := projects.Create(client, projects.CreateOpts{
		Name:        name,
		Description: "OSPA e2e test project",
		Enabled:     gophercloud.Enabled,
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test project: %v", err)
	}
	t.Logf("Created test project: %s (%s)", p.Name, p.ID)
	return p.ID, func() {
		t.Logf("Cleaning up test project: %s", p.ID)
		if err := projects.Delete(client, p.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete project %s: %v", p.ID, err)
		}
	}
}

func CreateGroup(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%sgroup-%d", testPrefix, time.Now().UnixNano())
	g, err := groups.Create(client, groups.CreateOpts{
		Name:        name,
		Description: "OSPA e2e test group",
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test group: %v", err)
	}
	t.Logf("Created test group: %s (%s)", g.Name, g.ID)
	return g.ID, func() {
		t.Logf("Cleaning up test group: %s", g.ID)
		if err := groups.Delete(client, g.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete group %s: %v", g.ID, err)
		}
	}
}

func CreateRole(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%srole-%d", testPrefix, time.Now().UnixNano())
	r, err := roles.Create(client, roles.CreateOpts{
		Name: name,
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	t.Logf("Created test role: %s (%s)", r.Name, r.ID)
	return r.ID, func() {
		t.Logf("Cleaning up test role: %s", r.ID)
		if err := roles.Delete(client, r.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete role %s: %v", r.ID, err)
		}
	}
}

func CreateDomain(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%sdomain-%d", testPrefix, time.Now().UnixNano())
	enabled := true
	d, err := domains.Create(client, domains.CreateOpts{
		Name:        name,
		Description: "OSPA e2e test domain",
		Enabled:     &enabled,
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test domain: %v", err)
	}
	t.Logf("Created test domain: %s (%s)", d.Name, d.ID)
	return d.ID, func() {
		t.Logf("Cleaning up test domain: %s", d.ID)
		// Domains must be disabled before delete.
		disabled := false
		if _, err := domains.Update(client, d.ID, domains.UpdateOpts{Enabled: &disabled}).Extract(); err != nil {
			t.Logf("Warning: failed to disable domain %s: %v", d.ID, err)
		}
		if err := domains.Delete(client, d.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete domain %s: %v", d.ID, err)
		}
	}
}

func CreateService(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("%sservice-%d", testPrefix, time.Now().UnixNano())
	enabled := true
	s, err := services.Create(client, services.CreateOpts{
		Type:    "ospa-e2e-test",
		Enabled: &enabled,
		Extra: map[string]interface{}{
			"name":        name,
			"description": "OSPA e2e test service",
		},
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}
	t.Logf("Created test service: %s (%s)", name, s.ID)
	return s.ID, func() {
		t.Logf("Cleaning up test service: %s", s.ID)
		if err := services.Delete(client, s.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete service %s: %v", s.ID, err)
		}
	}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	cleanupNamed(t, "users", func() {
		pages, err := users.List(client, users.ListOpts{}).AllPages()
		if err != nil {
			return
		}
		list, _ := users.ExtractUsers(pages)
		for _, u := range list {
			if strings.HasPrefix(u.Name, testPrefix) {
				_ = users.Delete(client, u.ID).ExtractErr()
			}
		}
	})
	cleanupNamed(t, "projects", func() {
		pages, err := projects.List(client, projects.ListOpts{}).AllPages()
		if err != nil {
			return
		}
		list, _ := projects.ExtractProjects(pages)
		for _, p := range list {
			if strings.HasPrefix(p.Name, testPrefix) {
				_ = projects.Delete(client, p.ID).ExtractErr()
			}
		}
	})
	cleanupNamed(t, "groups", func() {
		pages, err := groups.List(client, groups.ListOpts{}).AllPages()
		if err != nil {
			return
		}
		list, _ := groups.ExtractGroups(pages)
		for _, g := range list {
			if strings.HasPrefix(g.Name, testPrefix) {
				_ = groups.Delete(client, g.ID).ExtractErr()
			}
		}
	})
	cleanupNamed(t, "roles", func() {
		pages, err := roles.List(client, nil).AllPages()
		if err != nil {
			return
		}
		list, _ := roles.ExtractRoles(pages)
		for _, r := range list {
			if strings.HasPrefix(r.Name, testPrefix) {
				_ = roles.Delete(client, r.ID).ExtractErr()
			}
		}
	})
}

func cleanupNamed(t *testing.T, kind string, fn func()) {
	t.Helper()
	t.Logf("Cleaning orphan keystone %s", kind)
	fn()
}
