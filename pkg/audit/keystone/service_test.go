package keystone

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/services"
)

func TestServiceAuditor_ResourceType(t *testing.T) {
	auditor := &ServiceAuditor{}
	if got := auditor.ResourceType(); got != "service" {
		t.Errorf("ResourceType() = %q, want %q", got, "service")
	}
}

func TestServiceAuditor_Check_StatusDisabled(t *testing.T) {
	auditor := &ServiceAuditor{}
	s := services.Service{ID: "svc-123", Type: "compute", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-services",
		Check: policy.CheckConditions{Status: "disabled"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for disabled service")
	}
	if result.ResourceName != "compute" {
		t.Errorf("ResourceName = %q, want %q (fallback to Type)", result.ResourceName, "compute")
	}
}

func TestServiceAuditor_Check_NameFromExtra(t *testing.T) {
	auditor := &ServiceAuditor{}
	s := services.Service{ID: "svc-123", Type: "compute", Extra: map[string]interface{}{"name": "nova"}}

	rule := &policy.Rule{
		Name:  "find-services",
		Check: policy.CheckConditions{ExemptNames: []string{"nova"}},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt service named via Extra")
	}
	if result.ResourceName != "nova" {
		t.Errorf("ResourceName = %q, want %q", result.ResourceName, "nova")
	}
}

func TestServiceAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ServiceAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-service", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestServiceAuditor_Fix_Log(t *testing.T) {
	auditor := &ServiceAuditor{}
	s := services.Service{ID: "svc-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestServiceAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ServiceAuditor{}
	s := services.Service{ID: "svc-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestServiceAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ServiceAuditor{}
	s := services.Service{ID: "svc-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
