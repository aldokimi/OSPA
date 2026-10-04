//go:build e2e

package octavia

import (
	"testing"

	"github.com/gophercloud/gophercloud"
)

const testPrefix = "ospa-e2e-"

func CreateLoadbalancer(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateLoadbalancer not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateListener(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateListener not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreatePool(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreatePool not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateMember(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateMember not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateHealthmonitor(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateHealthmonitor not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	t.Log("TODO: Implement orphan cleanup")
}
