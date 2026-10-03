package cinder

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/snapshots"
)

func TestSnapshotAuditor_ResourceType(t *testing.T) {
	auditor := &SnapshotAuditor{}
	if got := auditor.ResourceType(); got != "snapshot" {
		t.Errorf("ResourceType() = %q, want %q", got, "snapshot")
	}
}

func TestSnapshotAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &SnapshotAuditor{}
	s := snapshots.Snapshot{ID: "snap-123", Name: "test-snapshot", Status: "error"}

	rule := &policy.Rule{
		Name:  "find-error-snapshots",
		Check: policy.CheckConditions{Status: "error"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for error snapshot")
	}
	if result.ResourceID != "snap-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "snap-123")
	}
}

func TestSnapshotAuditor_Check_ExemptName(t *testing.T) {
	auditor := &SnapshotAuditor{}
	s := snapshots.Snapshot{ID: "snap-123", Name: "default", Status: "error"}

	rule := &policy.Rule{
		Name:  "find-error-snapshots",
		Check: policy.CheckConditions{Status: "error", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt snapshot")
	}
}

func TestSnapshotAuditor_Check_InvalidType(t *testing.T) {
	auditor := &SnapshotAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-snapshot", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestSnapshotAuditor_Fix_Log(t *testing.T) {
	auditor := &SnapshotAuditor{}
	s := snapshots.Snapshot{ID: "snap-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestSnapshotAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &SnapshotAuditor{}
	s := snapshots.Snapshot{ID: "snap-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestSnapshotAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &SnapshotAuditor{}
	s := snapshots.Snapshot{ID: "snap-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
