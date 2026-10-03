package nova

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
)

func TestFlavorAuditor_ResourceType(t *testing.T) {
	auditor := &FlavorAuditor{}
	if got := auditor.ResourceType(); got != "flavor" {
		t.Errorf("ResourceType() = %q, want %q", got, "flavor")
	}
}

func TestFlavorAuditor_Check_IsPublic(t *testing.T) {
	auditor := &FlavorAuditor{}
	f := flavors.Flavor{ID: "flv-123", Name: "m1.tiny", IsPublic: true}

	want := false
	rule := &policy.Rule{
		Name:  "find-public-flavors",
		Check: policy.CheckConditions{IsPublic: &want},
	}

	result, err := auditor.Check(context.Background(), f, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for public flavor when private is required")
	}
}

func TestFlavorAuditor_Check_ExemptName(t *testing.T) {
	auditor := &FlavorAuditor{}
	f := flavors.Flavor{ID: "flv-123", Name: "default", IsPublic: true}

	want := false
	rule := &policy.Rule{
		Name:  "find-public-flavors",
		Check: policy.CheckConditions{IsPublic: &want, ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), f, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt flavor")
	}
}

func TestFlavorAuditor_Check_InvalidType(t *testing.T) {
	auditor := &FlavorAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-flavor", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestFlavorAuditor_Fix_Log(t *testing.T) {
	auditor := &FlavorAuditor{}
	f := flavors.Flavor{ID: "flv-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, f, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestFlavorAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &FlavorAuditor{}
	f := flavors.Flavor{ID: "flv-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, f, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestFlavorAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &FlavorAuditor{}
	f := flavors.Flavor{ID: "flv-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, f, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
