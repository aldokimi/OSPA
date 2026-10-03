package keystone

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/domains"
)

func TestDomainAuditor_ResourceType(t *testing.T) {
	auditor := &DomainAuditor{}
	if got := auditor.ResourceType(); got != "domain" {
		t.Errorf("ResourceType() = %q, want %q", got, "domain")
	}
}

func TestDomainAuditor_Check_StatusDisabled(t *testing.T) {
	auditor := &DomainAuditor{}
	d := domains.Domain{ID: "dom-123", Name: "test-domain", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-domains",
		Check: policy.CheckConditions{Status: "disabled"},
	}

	result, err := auditor.Check(context.Background(), d, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for disabled domain")
	}
}

func TestDomainAuditor_Check_ExemptName(t *testing.T) {
	auditor := &DomainAuditor{}
	d := domains.Domain{ID: "dom-123", Name: "Default", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-domains",
		Check: policy.CheckConditions{Status: "disabled", ExemptNames: []string{"Default"}},
	}

	result, err := auditor.Check(context.Background(), d, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt domain")
	}
}

func TestDomainAuditor_Check_InvalidType(t *testing.T) {
	auditor := &DomainAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-domain", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestDomainAuditor_Fix_Log(t *testing.T) {
	auditor := &DomainAuditor{}
	d := domains.Domain{ID: "dom-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, d, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestDomainAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &DomainAuditor{}
	d := domains.Domain{ID: "dom-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, d, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestDomainAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &DomainAuditor{}
	d := domains.Domain{ID: "dom-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, d, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
