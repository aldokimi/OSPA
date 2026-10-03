package heat

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func TestSnapshotAuditor_ResourceType(t *testing.T) {
	auditor := &SnapshotAuditor{}
	if got := auditor.ResourceType(); got != "snapshot" {
		t.Errorf("ResourceType() = %q, want %q", got, "snapshot")
	}
}

func TestSnapshotAuditor_Check_AgeGT(t *testing.T) {
	auditor := &SnapshotAuditor{}
	snap := discoveryservices.HeatSnapshot{
		StackName:    "web",
		SnapshotTime: time.Now().Add(-45 * 24 * time.Hour),
	}

	rule := &policy.Rule{
		Name:  "find-old-snapshots",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), snap, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 45d-old snapshot with age_gt 30d")
	}
}

func TestSnapshotAuditor_Check_ExemptName(t *testing.T) {
	auditor := &SnapshotAuditor{}
	snap := discoveryservices.HeatSnapshot{
		StackName:    "system-web",
		SnapshotTime: time.Now().Add(-45 * 24 * time.Hour),
	}

	rule := &policy.Rule{
		Name: "find-old-snapshots",
		Check: policy.CheckConditions{
			AgeGT:       "30d",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), snap, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestSnapshotAuditor_Check_InvalidType(t *testing.T) {
	auditor := &SnapshotAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), 3.14, rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestSnapshotAuditor_Fix_Log(t *testing.T) {
	auditor := &SnapshotAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestSnapshotAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &SnapshotAuditor{}
	rule := &policy.Rule{Name: "test", Action: "delete"}
	snap := discoveryservices.HeatSnapshot{StackName: "web"}
	if err := auditor.Fix(context.Background(), nil, snap, rule); err == nil {
		t.Error("Fix(delete) expected not-supported error")
	}
}
