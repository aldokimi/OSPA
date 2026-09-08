//go:build e2e

// Package keystone contains e2e tests for the Keystone service.
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
// DEPENDENCY GRAPH FOR Keystone:
// =============================================================================

// User:
//   Description: Users
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// Role:
//   Description: Roles
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// Project:
//   Description: Projects
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// Domain:
//   Description: Domains
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// Group:
//   Description: Groups
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// Service:
//   Description: Services
//   Gophercloud: https://pkg.go.dev/github.com/gophercloud/gophercloud/openstack
//   OpenStack API: https://docs.openstack.org/api-ref/keystone

// =============================================================================

package keystone

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


// CreateUser creates a test user and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateUser(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateUser not implemented - implement in resource_creator.go")
	return "", func() {}
}


// CreateRole creates a test role and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateRole(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateRole not implemented - implement in resource_creator.go")
	return "", func() {}
}


// CreateProject creates a test project and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateProject(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateProject not implemented - implement in resource_creator.go")
	return "", func() {}
}


// CreateDomain creates a test domain and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateDomain(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateDomain not implemented - implement in resource_creator.go")
	return "", func() {}
}


// CreateGroup creates a test group and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateGroup(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateGroup not implemented - implement in resource_creator.go")
	return "", func() {}
}


// CreateService creates a test service and returns:
//   - resourceID: The ID of the created resource (for filtering audit results)
//   - cleanup: A function to delete the resource and its dependencies
func CreateService(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()
	
	// TODO: Implement resource creation
	// See the example above and the gophercloud documentation
	
	t.Skip("CreateService not implemented - implement in resource_creator.go")
	return "", func() {}
}


// =============================================================================
// CLEANUP HELPER
// =============================================================================

// CleanupOrphans deletes any leaked test resources (those with testPrefix).
// Run this manually if tests fail and leave resources behind:
//   go test -tags=e2e ./e2e/keystone/... -run TestCleanupOrphans
func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	
	// TODO: Implement cleanup for orphaned resources
	// List all resources, filter by testPrefix, delete them
	
	t.Log("TODO: Implement orphan cleanup")
}
