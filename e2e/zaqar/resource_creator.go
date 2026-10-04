//go:build e2e

package zaqar

import (
	"testing"

	"github.com/gophercloud/gophercloud"
)

const testPrefix = "ospa-e2e-"

func CreateQueue(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateQueue not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateMessage(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateMessage not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CreateSubscription(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	t.Skip("CreateSubscription not implemented - implement in resource_creator.go")
	return "", func() {}
}

func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	t.Log("TODO: Implement orphan cleanup")
}
