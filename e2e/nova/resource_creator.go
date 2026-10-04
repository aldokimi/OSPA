//go:build e2e

package nova

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
)

const testPrefix = "ospa-e2e-"

// CreateKeypair creates an SSH keypair. ResourceID is the keypair name.
func CreateKeypair(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	name := fmt.Sprintf("%skeypair-%d", testPrefix, time.Now().UnixNano())
	kp, err := keypairs.Create(client, keypairs.CreateOpts{Name: name}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test keypair: %v", err)
	}
	t.Logf("Created test keypair: %s", kp.Name)

	return kp.Name, func() {
		t.Logf("Cleaning up test keypair: %s", kp.Name)
		if err := keypairs.Delete(client, kp.Name, nil).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete keypair %s: %v", kp.Name, err)
		}
	}
}

// CreateFlavor creates a tiny private flavor (admin required).
func CreateFlavor(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	name := fmt.Sprintf("%sflavor-%d", testPrefix, time.Now().UnixNano())
	isPublic := false
	disk := 0
	f, err := flavors.Create(client, flavors.CreateOpts{
		Name:     name,
		RAM:      64,
		VCPUs:    1,
		Disk:     &disk,
		IsPublic: &isPublic,
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test flavor: %v", err)
	}
	t.Logf("Created test flavor: %s (%s)", f.Name, f.ID)
	return f.ID, func() {
		t.Logf("Cleaning up test flavor: %s", f.ID)
		if err := flavors.Delete(client, f.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete flavor %s: %v", f.ID, err)
		}
	}
}

// CreateInstance boots a micro instance using an available image/flavor/network.
func CreateInstance(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	imageID := findBootImage(t, client)
	flavorID := findOrCreateTinyFlavor(t, client)
	networkID := findAnyNetwork(t, client)

	name := fmt.Sprintf("%sinstance-%d", testPrefix, time.Now().UnixNano())
	server, err := servers.Create(client, servers.CreateOpts{
		Name:      name,
		ImageRef:  imageID,
		FlavorRef: flavorID,
		Networks:  []servers.Network{{UUID: networkID}},
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test instance: %v", err)
	}
	t.Logf("Created test instance: %s (%s)", server.Name, server.ID)

	deadline := time.Now().Add(2 * time.Minute)
	for {
		current, getErr := servers.Get(client, server.ID).Extract()
		if getErr == nil && (current.Status == "ACTIVE" || current.Status == "ERROR") {
			if current.Status == "ERROR" {
				_ = servers.Delete(client, server.ID).ExtractErr()
				t.Fatalf("Test instance entered ERROR state")
			}
			break
		}
		if time.Now().After(deadline) {
			_ = servers.Delete(client, server.ID).ExtractErr()
			t.Fatalf("Timed out waiting for instance %s", server.ID)
		}
		time.Sleep(2 * time.Second)
	}

	return server.ID, func() {
		t.Logf("Cleaning up test instance: %s", server.ID)
		if err := servers.Delete(client, server.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete instance %s: %v", server.ID, err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := servers.Get(client, server.ID).Extract(); err != nil {
				return
			}
			time.Sleep(time.Second)
		}
	}
}

// CreateHypervisor cannot create hypervisors via API.
func CreateHypervisor(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	_ = client
	t.Skip("CreateHypervisor not applicable — hypervisors are infrastructure inventory")
	return "", func() {}
}

// CreateServer aliases CreateInstance for scaffolded callers.
func CreateServer(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	return CreateInstance(t, client)
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	if pages, err := servers.List(client, servers.ListOpts{}).AllPages(); err == nil {
		list, _ := servers.ExtractServers(pages)
		for _, s := range list {
			if strings.HasPrefix(s.Name, testPrefix) {
				t.Logf("Deleting orphan instance %s", s.ID)
				_ = servers.Delete(client, s.ID).ExtractErr()
			}
		}
	}
	if kpPages, err := keypairs.List(client, nil).AllPages(); err == nil {
		list, _ := keypairs.ExtractKeyPairs(kpPages)
		for _, kp := range list {
			if strings.HasPrefix(kp.Name, testPrefix) {
				t.Logf("Deleting orphan keypair %s", kp.Name)
				_ = keypairs.Delete(client, kp.Name, nil).ExtractErr()
			}
		}
	}
	if fPages, err := flavors.ListDetail(client, flavors.ListOpts{}).AllPages(); err == nil {
		list, _ := flavors.ExtractFlavors(fPages)
		for _, f := range list {
			if strings.HasPrefix(f.Name, testPrefix) {
				t.Logf("Deleting orphan flavor %s", f.ID)
				_ = flavors.Delete(client, f.ID).ExtractErr()
			}
		}
	}
}

func findBootImage(t *testing.T, client *gophercloud.ServiceClient) string {
	t.Helper()
	glance, err := openstack.NewImageServiceV2(client.ProviderClient, gophercloud.EndpointOpts{})
	if err != nil {
		t.Skipf("Cannot resolve glance client for instance boot: %v", err)
	}
	all, err := images.List(glance, images.ListOpts{Status: images.ImageStatusActive}).AllPages()
	if err != nil {
		t.Skipf("Cannot list images: %v", err)
	}
	imgs, err := images.ExtractImages(all)
	if err != nil || len(imgs) == 0 {
		t.Skipf("No active images available to boot instance: %v", err)
	}
	for _, needle := range []string{"cirros", "cirros-0"} {
		for _, img := range imgs {
			if strings.Contains(strings.ToLower(img.Name), needle) {
				return img.ID
			}
		}
	}
	return imgs[0].ID
}

func findOrCreateTinyFlavor(t *testing.T, client *gophercloud.ServiceClient) string {
	t.Helper()
	pages, err := flavors.ListDetail(client, flavors.ListOpts{}).AllPages()
	if err == nil {
		list, _ := flavors.ExtractFlavors(pages)
		for _, name := range []string{"m1.tiny", "cirros256", "ds512M", "tiny"} {
			for _, f := range list {
				if strings.EqualFold(f.Name, name) {
					return f.ID
				}
			}
		}
		if len(list) > 0 {
			return list[0].ID
		}
	}
	id, cleanup := CreateFlavor(t, client)
	t.Cleanup(cleanup)
	return id
}

func findAnyNetwork(t *testing.T, client *gophercloud.ServiceClient) string {
	t.Helper()
	neutron, err := openstack.NewNetworkV2(client.ProviderClient, gophercloud.EndpointOpts{})
	if err != nil {
		t.Skipf("Cannot resolve neutron client for instance boot: %v", err)
	}
	pages, err := networks.List(neutron, networks.ListOpts{}).AllPages()
	if err != nil {
		t.Skipf("Cannot list networks: %v", err)
	}
	nets, err := networks.ExtractNetworks(pages)
	if err != nil || len(nets) == 0 {
		t.Skipf("No network available for instance boot: %v", err)
	}
	for _, n := range nets {
		if strings.Contains(strings.ToLower(n.Name), "private") {
			return n.ID
		}
	}
	return nets[0].ID
}
