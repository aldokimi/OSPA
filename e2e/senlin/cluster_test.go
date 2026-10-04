//go:build e2e

package senlin

// =============================================================================
// Cluster E2E TESTS
// =============================================================================
//
// BEFORE WRITING TESTS:
// 1. Implement CreateCluster() in resource_creator.go
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
//   OS_CLOUD=mycloud go test -tags=e2e ./e2e/senlin/... -v -run Cluster
//
// =============================================================================

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/e2e"
)

// TestSenlin_Cluster_StatusCheck verifies status-based auditing.
func TestSenlin_Cluster_StatusCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-status
      description: Find cluster by status
      resource: cluster
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
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

// TestSenlin_Cluster_AgeGTCheck verifies age-based auditing.
func TestSenlin_Cluster_AgeGTCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-age
      description: Find cluster older than 30 days
      resource: cluster
      check:
        age_gt: 30d
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
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

// TestSenlin_Cluster_UnusedCheck verifies unused detection.
func TestSenlin_Cluster_UnusedCheck(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-unused
      description: Find unused cluster
      resource: cluster
      check:
        unused: true
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	// TODO: Assert based on resource-specific unused semantics
}

// TestSenlin_Cluster_ExemptNames verifies name exemptions work.
func TestSenlin_Cluster_ExemptNames(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-exempt
      description: Test exemption by name prefix
      resource: cluster
      check:
        status: ACTIVE
        exempt_names:
          - ospa-e2e-*
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	if resourceResults.Violations > 0 {
		t.Error("Expected resource to be exempt by name")
	}
}

// TestSenlin_Cluster_Discovery verifies batch discovery.
func TestSenlin_Cluster_Discovery(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	id1, cleanup1 := CreateCluster(t, client)
	defer cleanup1()
	id2, cleanup2 := CreateCluster(t, client)
	defer cleanup2()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-discovery
      description: Discover cluster resources
      resource: cluster
      check:
        status: ACTIVE
      action: log`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	r1 := results.FilterByService("senlin").FilterByResourceType("cluster").FilterByResourceID(id1)
	r2 := results.FilterByService("senlin").FilterByResourceType("cluster").FilterByResourceID(id2)

	if r1.Scanned == 0 {
		t.Error("First resource was not discovered")
	}
	if r2.Scanned == 0 {
		t.Error("Second resource was not discovered")
	}
}

// TestSenlin_Cluster_Classification verifies severity/category/guide_ref propagation.
func TestSenlin_Cluster_Classification(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-classify
      description: Test classification fields
      resource: cluster
      check:
        status: ACTIVE
      action: log
      severity: high
      category: security
      guide_ref: TEST-001`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}
	resourceResults.AssertClassification(t, "high", "security", "TEST-001")

	// TODO: Replace TEST-001 with a real OpenStack Security Guide reference for this resource
}

// TestSenlin_Cluster_OutputJSON verifies JSON output contains required fields.
func TestSenlin_Cluster_OutputJSON(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	_, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-json
      description: Output format test
      resource: cluster
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

// TestSenlin_Cluster_OutputCSV verifies CSV output has the correct headers.
func TestSenlin_Cluster_OutputCSV(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	_, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-csv
      description: Output format test
      resource: cluster
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

// TestSenlin_Cluster_DeleteAction verifies delete remediation.
func TestSenlin_Cluster_DeleteAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-delete
      description: Delete cluster resources
      resource: cluster
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during delete: %d", resourceResults.Errors)
	}

	// TODO: Verify the resource was actually deleted (e.g. GET returns 404)
}

// TestSenlin_Cluster_TagAction verifies tag remediation.
func TestSenlin_Cluster_TagAction(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-tag
      description: Tag cluster resources
      resource: cluster
      check:
        status: ACTIVE
      action: tag
      tag_name: ospa-e2e-tagged`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Errors > 0 {
		t.Errorf("Unexpected errors during tag: %d", resourceResults.Errors)
	}

	// TODO: Verify the tag was actually applied (e.g. GET resource, check tags list)
}

// TestSenlin_Cluster_DryRunSkip verifies dry-run skips remediation.
func TestSenlin_Cluster_DryRunSkip(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = false
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-dryrun
      description: Dry run delete
      resource: cluster
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)
	resourceResults.AssertRemediationSkipped(t, "dry-run")

	// TODO: Verify the resource still exists after dry-run (e.g. GET returns 200)
}

// TestSenlin_Cluster_AllowActionsFiltering verifies the allow-actions filter.
func TestSenlin_Cluster_AllowActionsFiltering(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	engine.Apply = true
	engine.AllowActions = []string{"tag"}
	client := engine.GetSenlinClient(t)

	resourceID, cleanup := CreateCluster(t, client)
	defer cleanup()

	policyYAML := `version: v1
defaults:
  workers: 2
policies:
  - senlin:
    - name: test-cluster-allowlist
      description: Delete not in allowlist
      resource: cluster
      check:
        unused: true
      action: delete`

	policy := engine.LoadPolicyFromYAML(t, policyYAML)
	results := engine.RunAudit(t, policy)

	resourceResults := results.FilterByService("senlin").
		FilterByResourceType("cluster").
		FilterByResourceID(resourceID)

	resourceResults.LogSummary(t)

	if resourceResults.Scanned == 0 {
		t.Error("Expected resource to be scanned")
	}

	resourceResults.AssertRemediationSkipped(t, "action_not_allowed")
}

// TestCleanup_Cluster cleans up orphaned test resources.
// Run manually: go test -tags=e2e ./e2e/senlin/... -run TestCleanup
func TestCleanup_Cluster(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cleanup in short mode")
	}

	engine := e2e.NewTestEngine(t)
	client := engine.GetSenlinClient(t)

	CleanupOrphans(t, client)
}
