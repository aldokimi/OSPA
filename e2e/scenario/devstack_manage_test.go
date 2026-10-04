//go:build e2e

package scenario

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/e2e"
	"github.com/OpenStack-Policy-Agent/OSPA/e2e/neutron"
	"github.com/OpenStack-Policy-Agent/OSPA/e2e/nova"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/imagedata"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
)

// TestDevStack_CreateAuditManage is the full local-DevStack workflow:
// create resources → audit with OSPA policy → remediate (apply delete) → re-audit.
//
//	OS_CLOUD=devstack go test -tags=e2e ./e2e/scenario/... -v -run CreateAuditManage
func TestDevStack_CreateAuditManage(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	netClient := engine.GetNetworkClient(t)
	imgClient := engine.GetImageClient(t)
	computeClient := engine.GetComputeClient(t)

	unusedSGID, cleanupUnusedSG := neutron.CreateSecurityGroup(t, netClient)
	defer func() {
		// May already be deleted by apply remediation.
		if _, err := groups.Get(netClient, unusedSGID).Extract(); err == nil {
			cleanupUnusedSG()
		}
	}()

	// SSH fixture is created for dry-run, then removed before apply so the
	// unused-SG delete action does not also remove the rule's parent group.
	sshRuleID, cleanupSSH := createSSHWorldRule(t, netClient)

	keypairName, cleanupKP := nova.CreateKeypair(t, computeClient)
	t.Cleanup(cleanupKP)

	publicImageID, cleanupImg := createPublicImage(t, imgClient)
	t.Cleanup(cleanupImg)

	t.Logf("fixtures: unusedSG=%s sshRule=%s keypair=%s publicImage=%s",
		unusedSGID, sshRuleID, keypairName, publicImageID)

	policyPath := resolveManagePolicy(t)
	p := engine.LoadPolicy(t, policyPath)

	// Dry-run: expect violations for created fixtures.
	engine.Apply = false
	dry := engine.RunAudit(t, p)
	dry.LogSummary(t)

	assertViolation(t, dry, "neutron", "security_group_rule", sshRuleID, "manage-ssh-open-to-world")
	assertViolation(t, dry, "neutron", "security_group", unusedSGID, "manage-unused-security-group")
	assertViolation(t, dry, "glance", "image", publicImageID, "manage-public-image")
	assertScanned(t, dry, "nova", "keypair", keypairName)

	cleanupSSH()

	// Apply: delete unused security group via policy action.
	engine.Apply = true
	engine.AllowActions = []string{"delete", "log"}
	applied := engine.RunAudit(t, p)
	applied.LogSummary(t)

	sgResults := applied.FilterByService("neutron").
		FilterByResourceType("security_group").
		FilterByResourceID(unusedSGID).
		FilterByRuleID("manage-unused-security-group")
	if sgResults.Scanned == 0 {
		t.Fatalf("expected unused SG %s to be scanned during apply", unusedSGID)
	}
	if sgResults.Violations == 0 {
		t.Fatalf("expected unused SG %s to violate during apply", unusedSGID)
	}
	for _, r := range sgResults.Results {
		if r.RemediationError != nil {
			t.Errorf("remediation error for SG %s: %v", unusedSGID, r.RemediationError)
		}
		if !r.Remediated && r.RemediationError == nil && !r.RemediationSkipped {
			t.Errorf("expected remediation attempt for unused SG %s", unusedSGID)
		}
	}
	if _, err := groups.Get(netClient, unusedSGID).Extract(); err == nil {
		t.Fatalf("unused security group %s still exists after apply delete", unusedSGID)
	} else {
		t.Logf("unused SG deleted as expected")
	}

	// Recreate SSH fixture for post-remediation audit of log-only rules.
	sshRuleID, cleanupSSH = createSSHWorldRule(t, netClient)
	t.Cleanup(cleanupSSH)

	// Re-audit: unused SG gone; other fixtures still violate.
	engine.Apply = false
	engine.AllowActions = nil
	again := engine.RunAudit(t, p)
	againSG := again.FilterByService("neutron").
		FilterByResourceType("security_group").
		FilterByResourceID(unusedSGID)
	if againSG.Scanned > 0 {
		t.Errorf("unused SG %s still discovered after remediation", unusedSGID)
	}
	assertViolation(t, again, "neutron", "security_group_rule", sshRuleID, "manage-ssh-open-to-world")
	assertViolation(t, again, "glance", "image", publicImageID, "manage-public-image")
}

// TestDevStack_CLIAgentManage loads the packaged policy file and audits a fixture.
func TestDevStack_CLIAgentManage(t *testing.T) {
	engine := e2e.NewTestEngine(t)
	netClient := engine.GetNetworkClient(t)

	ruleID, cleanup := createSSHWorldRule(t, netClient)
	t.Cleanup(cleanup)

	p := engine.LoadPolicy(t, resolveManagePolicy(t))
	results := engine.RunAudit(t, p)
	assertViolation(t, results, "neutron", "security_group_rule", ruleID, "manage-ssh-open-to-world")
}

func createSSHWorldRule(t *testing.T, client *gophercloud.ServiceClient) (ruleID string, cleanup func()) {
	t.Helper()
	opts := rules.CreateOpts{
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "0.0.0.0/0",
		Description:    "OSPA scenario SSH world-open - safe to delete",
	}
	id, _, cleanup := neutron.CreateSecurityGroupRuleWithOptions(t, client, opts)
	return id, cleanup
}

func createPublicImage(t *testing.T, client *gophercloud.ServiceClient) (imageID string, cleanup func()) {
	t.Helper()
	name := fmt.Sprintf("ospa-e2e-public-img-%d", time.Now().UnixNano())
	vis := images.ImageVisibilityPrivate
	img, err := images.Create(client, images.CreateOpts{
		Name:            name,
		DiskFormat:      "raw",
		ContainerFormat: "bare",
		Visibility:      &vis,
	}).Extract()
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := imagedata.Upload(client, img.ID, bytes.NewReader([]byte("ospa-scenario"))).ExtractErr(); err != nil {
		_ = images.Delete(client, img.ID).ExtractErr()
		t.Fatalf("upload image: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		cur, getErr := images.Get(client, img.ID).Extract()
		if getErr == nil && string(cur.Status) == "active" {
			break
		}
		if time.Now().After(deadline) {
			_ = images.Delete(client, img.ID).ExtractErr()
			t.Fatalf("image not active: %v", getErr)
		}
		time.Sleep(400 * time.Millisecond)
	}
	pub := images.ImageVisibilityPublic
	if _, err := images.Update(client, img.ID, images.UpdateOpts{
		images.UpdateVisibility{Visibility: pub},
	}).Extract(); err != nil {
		_ = images.Delete(client, img.ID).ExtractErr()
		t.Fatalf("set public visibility: %v", err)
	}
	return img.ID, func() {
		_ = images.Delete(client, img.ID).ExtractErr()
	}
}

func resolveManagePolicy(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("OSPA_MANAGE_POLICY"); p != "" {
		return p
	}
	candidates := []string{
		"examples/policies/devstack-manage.yaml",
		"../../examples/policies/devstack-manage.yaml",
		filepath.Join("..", "..", "examples", "policies", "devstack-manage.yaml"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("examples/policies/devstack-manage.yaml not found; set OSPA_MANAGE_POLICY")
	return ""
}

func assertViolation(t *testing.T, results *e2e.AuditResults, service, resourceType, resourceID, ruleID string) {
	t.Helper()
	filtered := results.FilterByService(service).
		FilterByResourceType(resourceType).
		FilterByResourceID(resourceID).
		FilterByRuleID(ruleID)
	filtered.LogSummary(t)
	if filtered.Scanned == 0 {
		t.Fatalf("expected %s/%s %s under rule %s to be scanned", service, resourceType, resourceID, ruleID)
	}
	if filtered.Violations == 0 {
		t.Fatalf("expected violation for %s/%s %s under rule %s", service, resourceType, resourceID, ruleID)
	}
}

func assertScanned(t *testing.T, results *e2e.AuditResults, service, resourceType, resourceID string) {
	t.Helper()
	filtered := results.FilterByService(service).
		FilterByResourceType(resourceType).
		FilterByResourceID(resourceID)
	if filtered.Scanned == 0 {
		t.Fatalf("expected %s/%s %s to be discovered", service, resourceType, resourceID)
	}
}
