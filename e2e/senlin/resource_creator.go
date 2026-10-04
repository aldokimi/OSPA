//go:build e2e

package senlin

import (
	"testing"

	"github.com/gophercloud/gophercloud"
)

const testPrefix = "ospa-e2e-"

func CreateCluster(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateCluster not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateProfile(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateProfile not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateNode(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateNode not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreatePolicy(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreatePolicy not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	t.Log("TODO: Implement orphan cleanup")
}
