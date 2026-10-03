package nova

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/hypervisors"
)

func TestHypervisorAuditor_ResourceType(t *testing.T) {
	auditor := &HypervisorAuditor{}
	if got := auditor.ResourceType(); got != "hypervisor" {
		t.Errorf("ResourceType() = %q, want %q", got, "hypervisor")
	}
}

func TestHypervisorAuditor_Check_StatusDown(t *testing.T) {
	auditor := &HypervisorAuditor{}
	h := hypervisors.Hypervisor{ID: "hv-1", HypervisorHostname: "compute-1", State: "down"}

	rule := &policy.Rule{
		Name:  "find-down-hypervisors",
		Check: policy.CheckConditions{Status: "down"},
	}

	result, err := auditor.Check(context.Background(), h, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for down hypervisor")
	}
	if result.ResourceName != "compute-1" {
		t.Errorf("ResourceName = %q, want %q", result.ResourceName, "compute-1")
	}
}

func TestHypervisorAuditor_Check_StatusUp(t *testing.T) {
	auditor := &HypervisorAuditor{}
	h := hypervisors.Hypervisor{ID: "hv-1", HypervisorHostname: "compute-1", State: "up"}

	rule := &policy.Rule{
		Name:  "find-down-hypervisors",
		Check: policy.CheckConditions{Status: "down"},
	}

	result, err := auditor.Check(context.Background(), h, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for up hypervisor")
	}
}

func TestHypervisorAuditor_Check_InvalidType(t *testing.T) {
	auditor := &HypervisorAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-hypervisor", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestHypervisorAuditor_Fix_Log(t *testing.T) {
	auditor := &HypervisorAuditor{}
	h := hypervisors.Hypervisor{ID: "hv-1"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, h, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestHypervisorAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &HypervisorAuditor{}
	h := hypervisors.Hypervisor{ID: "hv-1"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, h, rule); err == nil {
		t.Error("Fix(delete) expected error: hypervisors have no delete API")
	}
}
