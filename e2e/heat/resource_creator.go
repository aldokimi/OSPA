//go:build e2e

// Package heat contains e2e tests for the Heat service.
//
// =============================================================================
// RESOURCE CREATOR - READ THIS FIRST
// =============================================================================
//
// This file provides helper functions to create test resources for e2e tests.
// Each resource may have dependencies that must be created first.
//
// HOW TO USE:
// 1. Implement the Create<Resource>() functions below
// 2. Each function should create the resource AND its dependencies
// 3. Return a cleanup function that deletes resources in reverse order
// 4. Use these functions in the corresponding <resource>_test.go files
//
// DEPENDENCY GRAPH FOR Heat:
// =============================================================================

// Stack:
//   Description: Stacks
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/heat

// Resource:
//   Description: Stack resources
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/heat

// Template:
//   Description: Templates
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/heat

// Snapshot:
//   Description: Stack snapshots
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/heat

// =============================================================================

package heat

import (
	"testing"

	"github.com/gophercloud/gophercloud"
	// TODO: Import the specific gophercloud packages you need:
	// "github.com/gophercloud/gophercloud/openstack/<service>/<version>/<resource>"
)

const testPrefix = "ospa-e2e-"

// =============================================================================
// RESOURCE CREATORS - IMPLEMENT THESE
// =============================================================================

// CreateStack creates a test stack and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateStack(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation

	t.Skip("CreateStack not implemented - implement in resource_creator.go")
	return "", func() {}
}

// CreateResource creates a test resource and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateResource(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation

	t.Skip("CreateResource not implemented - implement in resource_creator.go")
	return "", func() {}
}

// CreateTemplate creates a test template and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateTemplate(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation

	t.Skip("CreateTemplate not implemented - implement in resource_creator.go")
	return "", func() {}
}

// CreateSnapshot creates a test snapshot and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateSnapshot(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation

	t.Skip("CreateSnapshot not implemented - implement in resource_creator.go")
	return "", func() {}
}

// =============================================================================
// CLEANUP HELPER
// =============================================================================

// CleanupOrphans deletes any leaked test resources (those with testPrefix).
// Run this manually if tests fail and leave resources behind:
//
//	go test -tags=e2e ./e2e/heat/... -run TestCleanupOrphans
func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()

	// TODO: Implement cleanup for orphaned resources
	// List all resources, filter by testPrefix, delete them

	t.Log("TODO: Implement orphan cleanup")
}
