package trove

import (
	"context"
	"strings"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/db/v1/instances"
)

func TestBackupAuditor_RetentionExceeded(t *testing.T) {
	auditor := &BackupAuditor{}
	b := discoveryservices.TroveBackup{
		ID:      "bk-1",
		Name:    "old-backup",
		Created: time.Now().Add(-40 * 24 * time.Hour),
		Updated: time.Now().Add(-40 * 24 * time.Hour),
	}

	rule := &policy.Rule{
		Name:  "retention",
		Check: policy.CheckConditions{BackupRetentionDays: 30},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for backup exceeding retention")
	}
	if !strings.Contains(result.Observation, "backup_retention_exceeded") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}

func TestInstanceAuditor_Status(t *testing.T) {
	auditor := &InstanceAuditor{}
	inst := instances.Instance{ID: "db-1", Name: "mysql", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-instances",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), inst, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for ERROR instance")
	}
}
