package barbican

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/orders"
)

func TestOrderAuditor_ResourceType(t *testing.T) {
	auditor := &OrderAuditor{}
	if got := auditor.ResourceType(); got != "order" {
		t.Errorf("ResourceType() = %q, want %q", got, "order")
	}
}

func TestOrderAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &OrderAuditor{}
	o := orders.Order{OrderRef: "https://kms/v1/orders/abc-123", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-orders",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), o, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR order")
	}
	if result.ResourceID != "abc-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "abc-123")
	}
}

func TestOrderAuditor_Check_ExemptName(t *testing.T) {
	auditor := &OrderAuditor{}
	o := orders.Order{OrderRef: "https://kms/v1/orders/abc-123", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-orders",
		Check: policy.CheckConditions{Status: "ERROR", ExemptNames: []string{"abc-123"}},
	}

	result, err := auditor.Check(context.Background(), o, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt order")
	}
}

func TestOrderAuditor_Check_InvalidType(t *testing.T) {
	auditor := &OrderAuditor{}

	_, err := auditor.Check(context.Background(), "not-an-order", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestOrderAuditor_Fix_Log(t *testing.T) {
	auditor := &OrderAuditor{}
	o := orders.Order{OrderRef: "https://kms/v1/orders/abc-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestOrderAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &OrderAuditor{}
	o := orders.Order{OrderRef: "https://kms/v1/orders/abc-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestOrderAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &OrderAuditor{}
	o := orders.Order{OrderRef: "https://kms/v1/orders/abc-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
