package ironic

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/ports"
)

func TestPortAuditor_ResourceType(t *testing.T) {
	auditor := &PortAuditor{}
	if got := auditor.ResourceType(); got != "port" {
		t.Errorf("ResourceType() = %q, want %q", got, "port")
	}
}

func TestPortAuditor_Check_ExemptName(t *testing.T) {
	auditor := &PortAuditor{}
	p := ports.Port{UUID: "port-123", Address: "aa:bb:cc:dd:ee:ff"}

	rule := &policy.Rule{
		Name:  "find-old-ports",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"aa:bb:cc:dd:ee:ff"}},
	}

	result, err := auditor.Check(context.Background(), p, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt port")
	}
	if result.ResourceID != "port-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "port-123")
	}
}

func TestPortAuditor_Check_InvalidType(t *testing.T) {
	auditor := &PortAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-port", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestPortAuditor_Fix_Log(t *testing.T) {
	auditor := &PortAuditor{}
	p := ports.Port{UUID: "port-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestPortAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &PortAuditor{}
	p := ports.Port{UUID: "port-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestPortAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &PortAuditor{}
	p := ports.Port{UUID: "port-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
