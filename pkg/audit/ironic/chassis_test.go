package ironic

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func TestChassisAuditor_ResourceType(t *testing.T) {
	auditor := &ChassisAuditor{}
	if got := auditor.ResourceType(); got != "chassis" {
		t.Errorf("ResourceType() = %q, want %q", got, "chassis")
	}
}

func TestChassisAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ChassisAuditor{}
	c := discoveryservices.Chassis{UUID: "ch-123", Description: "rack-1"}

	rule := &policy.Rule{
		Name:  "find-old-chassis",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"rack-1"}},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt chassis")
	}
	if result.ResourceID != "ch-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "ch-123")
	}
}

func TestChassisAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ChassisAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-chassis", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestChassisAuditor_Fix_Log(t *testing.T) {
	auditor := &ChassisAuditor{}
	c := discoveryservices.Chassis{UUID: "ch-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestChassisAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ChassisAuditor{}
	c := discoveryservices.Chassis{UUID: "ch-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestChassisAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ChassisAuditor{}
	c := discoveryservices.Chassis{UUID: "ch-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
