package ironic

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/drivers"
)

func TestDriverAuditor_ResourceType(t *testing.T) {
	auditor := &DriverAuditor{}
	if got := auditor.ResourceType(); got != "driver" {
		t.Errorf("ResourceType() = %q, want %q", got, "driver")
	}
}

func TestDriverAuditor_Check_ExemptName(t *testing.T) {
	auditor := &DriverAuditor{}
	d := drivers.Driver{Name: "ipmi"}

	rule := &policy.Rule{
		Name:  "find-drivers",
		Check: policy.CheckConditions{ExemptNames: []string{"ipmi"}},
	}

	result, err := auditor.Check(context.Background(), d, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt driver")
	}
	if result.Observation != "exempt by name" {
		t.Errorf("Observation = %q, want %q", result.Observation, "exempt by name")
	}
}

func TestDriverAuditor_Check_NotExempt(t *testing.T) {
	auditor := &DriverAuditor{}
	d := drivers.Driver{Name: "redfish"}

	rule := &policy.Rule{
		Name:  "find-drivers",
		Check: policy.CheckConditions{ExemptNames: []string{"ipmi"}},
	}

	result, err := auditor.Check(context.Background(), d, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.ResourceID != "redfish" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "redfish")
	}
}

func TestDriverAuditor_Check_InvalidType(t *testing.T) {
	auditor := &DriverAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-driver", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestDriverAuditor_Fix_Log(t *testing.T) {
	auditor := &DriverAuditor{}
	d := drivers.Driver{Name: "ipmi"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, d, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestDriverAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &DriverAuditor{}
	d := drivers.Driver{Name: "ipmi"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, d, rule); err == nil {
		t.Error("Fix(delete) expected error: drivers have no delete API")
	}
}
