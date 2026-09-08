//go:build e2e

package swift

// =============================================================================
// Object E2E TESTS
// =============================================================================
//
// BEFORE WRITING TESTS:
// 1. Implement CreateObject() in resource_creator.go
// 2. The creator should handle all dependencies (network, subnet, etc.)
// 3. The creator returns a cleanup function - always defer it!
//
// TEST COVERAGE CHECKLIST:
// - [x] Status check (status: ACTIVE, DOWN, ERROR, etc.)
// - [x] Age check (age_gt: 30d)
// - [x] Unused check (unused: true) - if applicable
// - [x] Exempt names (exempt_names: [...])
// - [x] Discovery (multiple resources)
// - [x] Classification propagation (severity/category/guide_ref)
// - [x] Output JSON
// - [x] Output CSV
// - [x] Delete action
// - [x] Tag action
// - [x] Dry-run remediation skip
// - [x] Allow-actions filtering
//
// RUNNING TESTS:
//   OS_CLOUD=mycloud go test -tags=e2e ./e2e/swift/... -v -run Object
//
// =============================================================================

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/e2e"
)

// TestSwift_Object_StatusCheck verifies status-based auditing.
func TestSwift_Object_StatusCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-status
      description: Find object by status
      resource: object
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}
	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors: %d", resourceResults.Errors)
	}

	// TODO: Adjust expected status for this resource type (e.g. "available", "in-use", "BUILD")
	// TODO: Add a non-compliant status test (create resource, check for a status it does NOT have)
}

// TestSwift_Object_AgeGTCheck verifies age-based auditing.
func TestSwift_Object_AgeGTCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-age
      description: Find object older than 30 days
      resource: object
      check:
        age_gt: 30d
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}
	// Freshly created resource should be compliant (younger than 30 days)
	if resourceResults.Violations > 0 {
		t.Error("Freshly created resource should not be flagged by age_gt: 30d")
	}

	// TODO: Add an AgeGTViolation test: create resource, audit with age_gt: 0m, expect violation
}

// TestSwift_Object_UnusedCheck verifies unused detection.
func TestSwift_Object_UnusedCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-unused
      description: Find unused object
      resource: object
      check:
        unused: true
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	// TODO: Assert based on resource-specific unused semantics
}

// TestSwift_Object_ExemptNames verifies name exemptions work.
func TestSwift_Object_ExemptNames(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-exempt
      description: Test exemption by name prefix
      resource: object
      check:
        status: ACTIVE
        exempt_names:
          - ospa-e2e-*
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	if resourceResults.Violations > 0 {
		t.Error("Expected resource to be exempt by name")
	}
}

// TestSwift_Object_Discovery verifies batch discovery.
func TestSwift_Object_Discovery(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	id1, cleanup1 := CreateObject(t, client)
	defer cleanup1()
	id2, cleanup2 := CreateObject(t, client)
	defer cleanup2()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-discovery
      description: Discover object resources
      resource: object
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	r1 := results.FilterByService("swift").FilterByResourceType("object").FilterByResourceID(id1)
	r2 := results.FilterByService("swift").FilterByResourceType("object").FilterByResourceID(id2)

	if r1.Scanned == 0 {
		t.Error("First resource was not discovered")
	}
	if r2.Scanned == 0 {
		t.Error("Second resource was not discovered")
	}
}

// TestSwift_Object_Classification verifies severity/category/guide_ref propagation.
func TestSwift_Object_Classification(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-classify
      description: Test classification fields
      resource: object
      check:
        status: ACTIVE
      action: log
      severity: high
      category: security
      guide_ref: TEST-001`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}
	resourceResults.AssertClassification(t, "high", "security", "TEST-001")

	// TODO: Replace TEST-001 with a real OpenStack Security Guide reference for this resource
}

// TestSwift_Object_OutputJSON verifies JSON output contains required fields.
func TestSwift_Object_OutputJSON(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	_, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-json
      description: Output format test
      resource: object
      check:
        status: ACTIVE
      action: log
      severity: medium
      category: compliance`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results, filePath := engine.RunAuditToFile(t, policy, "json")
	defer os.Remove(filePath)

	if results.Scanned == 0 {
		t.Skip("No resources scanned, cannot validate output")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read JSON output: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JSON output file is empty")
	}

	var finding map[string]interface{}
	if err := json.Unmarshal(data[:e2e.FindLineEnd(data)], &finding); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	for _, field := range []string{"rule_id", "resource_id", "compliant", "severity", "category"} {
		if _, ok := finding[field]; !ok {
			t.Errorf("JSON output missing required field: %s", field)
		}
	}
}

// TestSwift_Object_OutputCSV verifies CSV output has the correct headers.
func TestSwift_Object_OutputCSV(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	_, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-csv
      description: Output format test
      resource: object
      check:
        status: ACTIVE
      action: log
      severity: low
      category: hygiene`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results, filePath := engine.RunAuditToFile(t, policy, "csv")
	defer os.Remove(filePath)

	if results.Scanned == 0 {
		t.Skip("No resources scanned, cannot validate output")
	}

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("Failed to open CSV output: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		t.Fatalf("Failed to read CSV header: %v", err)
	}

	expected := map[string]bool{"rule_id": false, "resource_id": false, "compliant": false, "severity": false, "category": false, "guide_ref": false}
	for _, col := range header {
		if _, ok := expected[col]; ok {
			expected[col] = true
		}
	}
	for col, found := range expected {
		if !found {
			t.Errorf("CSV header missing expected column: %s", col)
		}
	}

	row, err := reader.Read()
	if err != nil {
		t.Fatalf("Failed to read CSV data row: %v", err)
	}
	if len(row) != len(header) {
		t.Errorf("CSV data row has %d columns, expected %d", len(row), len(header))
	}
}

// TestSwift_Object_DeleteAction verifies delete remediation.
func TestSwift_Object_DeleteAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-delete
      description: Delete object resources
      resource: object
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during delete: %d", resourceResults.Errors)
	}

	// TODO: Verify the resource was actually deleted (e.g. GET returns 404)
}

// TestSwift_Object_TagAction verifies tag remediation.
func TestSwift_Object_TagAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-tag
      description: Tag object resources
      resource: object
      check:
        status: ACTIVE
      action: tag
      tag_name: ospa-e2e-tagged`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during tag: %d", resourceResults.Errors)
	}

	// TODO: Verify the tag was actually applied (e.g. GET resource, check tags list)
}

// TestSwift_Object_DryRunSkip verifies dry-run skips remediation.
func TestSwift_Object_DryRunSkip(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = false
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-dryrun
      description: Dry run delete
      resource: object
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)
	resourceResults.AssertRemediationSkipped(t, "dry-run")

	// TODO: Verify the resource still exists after dry-run (e.g. GET returns 200)
}

// TestSwift_Object_AllowActionsFiltering verifies the allow-actions filter.
func TestSwift_Object_AllowActionsFiltering(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	engine.AllowActions = []string{"tag"}
	client := engine.GetObjectStorageClient(t)

	resourceID, cleanup := CreateObject(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - swift:
    - name: test-object-allowlist
      description: Delete not in allowlist
      resource: object
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("swift").
		FilterByResourceType("object").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}

	resourceResults.AssertRemediationSkipped(t, "action_not_allowed")
}

// TestCleanup_Object cleans up orphaned test resources.
// Run manually: go test -tags=e2e ./e2e/swift/... -run TestCleanup
func TestCleanup_Object(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cleanup in short mode")
	}

	engine := e2e.NewTestEngine(t)
	client := engine.GetObjectStorageClient(t)

	CleanupOrphans(t, client)
}
