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
		ID:         "b-1",
		Name:       "nightly",
		InstanceID: "i-1",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		UpdatedAt:  time.Now().Add(-48 * time.Hour),
	}
	rule := &policy.Rule{
		Name:  "old-backups",
		Check: policy.CheckConditions{AgeGT: "1d"},
	}
	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for old backup")
	}
	if !strings.Contains(result.Observation, "backup_retention_exceeded") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}

func TestInstanceAuditor_Status(t *testing.T) {
	auditor := &InstanceAuditor{}
	i := instances.Instance{ID: "i-1", Name: "db1", Status: "ERROR"}
	rule := &policy.Rule{
		Name:  "error-dbs",
		Check: policy.CheckConditions{Status: "ERROR"},
	}
	result, err := auditor.Check(context.Background(), i, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for ERROR instance")
	}
}

func TestClusterAuditor_Status(t *testing.T) {
	auditor := &ClusterAuditor{}
	c := discoveryservices.TroveCluster{ID: "c-1", Name: "cl", Status: "BUILDING"}
	rule := &policy.Rule{
		Name:  "building",
		Check: policy.CheckConditions{Status: "BUILDING"},
	}
	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant")
	}
}
