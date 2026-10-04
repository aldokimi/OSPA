//go:build e2e

package manila

import (
	"testing"

	"github.com/gophercloud/gophercloud"
)

const testPrefix = "ospa-e2e-"

func CreateShare(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateShare not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateShareSnapshot(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateShareSnapshot not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateShareNetwork(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateShareNetwork not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateShareServer(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateShareServer not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	t.Log("TODO: Implement orphan cleanup")
}
