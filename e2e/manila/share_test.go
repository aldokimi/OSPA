//go:build e2e

package manila

// =============================================================================
// Share E2E TESTS
// =============================================================================
//
// BEFORE WRITING TESTS:
// 1. Implement CreateShare() in resource_creator.go
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
//   OS_CLOUD=mycloud go test -tags=e2e ./e2e/manila/... -v -run Share
//
// =============================================================================

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/e2e"
)

// TestManila_Share_StatusCheck verifies status-based auditing.
func TestManila_Share_StatusCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-status
      description: Find share by status
      resource: share
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
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

// TestManila_Share_AgeGTCheck verifies age-based auditing.
func TestManila_Share_AgeGTCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-age
      description: Find share older than 30 days
      resource: share
      check:
        age_gt: 30d
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
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

// TestManila_Share_UnusedCheck verifies unused detection.
func TestManila_Share_UnusedCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-unused
      description: Find unused share
      resource: share
      check:
        unused: true
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	// TODO: Assert based on resource-specific unused semantics
}

// TestManila_Share_ExemptNames verifies name exemptions work.
func TestManila_Share_ExemptNames(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-exempt
      description: Test exemption by name prefix
      resource: share
      check:
        status: ACTIVE
        exempt_names:
          - ospa-e2e-*
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	if resourceResults.Violations > 0 {
		t.Error("Expected resource to be exempt by name")
	}
}

// TestManila_Share_Discovery verifies batch discovery.
func TestManila_Share_Discovery(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	id1, cleanup1 := CreateShare(t, client)
	defer cleanup1()
	id2, cleanup2 := CreateShare(t, client)
	defer cleanup2()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-discovery
      description: Discover share resources
      resource: share
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	r1 := results.FilterByService("manila").FilterByResourceType("share").FilterByResourceID(id1)
	r2 := results.FilterByService("manila").FilterByResourceType("share").FilterByResourceID(id2)

	if r1.Scanned == 0 {
		t.Error("First resource was not discovered")
	}
	if r2.Scanned == 0 {
		t.Error("Second resource was not discovered")
	}
}

// TestManila_Share_Classification verifies severity/category/guide_ref propagation.
func TestManila_Share_Classification(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-classify
      description: Test classification fields
      resource: share
      check:
        status: ACTIVE
      action: log
      severity: high
      category: security
      guide_ref: TEST-001`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}
	resourceResults.AssertClassification(t, "high", "security", "TEST-001")

	// TODO: Replace TEST-001 with a real OpenStack Security Guide reference for this resource
}

// TestManila_Share_OutputJSON verifies JSON output contains required fields.
func TestManila_Share_OutputJSON(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	_, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-json
      description: Output format test
      resource: share
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

// TestManila_Share_OutputCSV verifies CSV output has the correct headers.
func TestManila_Share_OutputCSV(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	_, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-csv
      description: Output format test
      resource: share
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

// TestManila_Share_DeleteAction verifies delete remediation.
func TestManila_Share_DeleteAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-delete
      description: Delete share resources
      resource: share
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during delete: %d", resourceResults.Errors)
	}

	// TODO: Verify the resource was actually deleted (e.g. GET returns 404)
}

// TestManila_Share_TagAction verifies tag remediation.
func TestManila_Share_TagAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-tag
      description: Tag share resources
      resource: share
      check:
        status: ACTIVE
      action: tag
      tag_name: ospa-e2e-tagged`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during tag: %d", resourceResults.Errors)
	}

	// TODO: Verify the tag was actually applied (e.g. GET resource, check tags list)
}

// TestManila_Share_DryRunSkip verifies dry-run skips remediation.
func TestManila_Share_DryRunSkip(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = false
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-dryrun
      description: Dry run delete
      resource: share
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)
	resourceResults.AssertRemediationSkipped(t, "dry-run")

	// TODO: Verify the resource still exists after dry-run (e.g. GET returns 200)
}

// TestManila_Share_AllowActionsFiltering verifies the allow-actions filter.
func TestManila_Share_AllowActionsFiltering(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	engine.AllowActions = []string{"tag"}
	client := engine.GetManilaClient(t)

	resourceID, cleanup := CreateShare(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - manila:
    - name: test-share-allowlist
      description: Delete not in allowlist
      resource: share
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("manila").
		FilterByResourceType("share").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}

	resourceResults.AssertRemediationSkipped(t, "action_not_allowed")
}

// TestCleanup_Share cleans up orphaned test resources.
// Run manually: go test -tags=e2e ./e2e/manila/... -run TestCleanup
func TestCleanup_Share(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cleanup in short mode")
	}

	engine := e2e.NewTestEngine(t)
	client := engine.GetManilaClient(t)

	CleanupOrphans(t, client)
}
