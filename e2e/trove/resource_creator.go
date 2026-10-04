//go:build e2e

package trove

import (
	"testing"

	"github.com/gophercloud/gophercloud"
)

const testPrefix = "ospa-e2e-"

func CreateInstance(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateInstance not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateCluster(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateCluster not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateBackup(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateBackup not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateDatastore(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateDatastore not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	t.Log("TODO: Implement orphan cleanup")
}
