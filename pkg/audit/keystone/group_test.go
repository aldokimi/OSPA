package keystone

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
)

func TestGroupAuditor_ResourceType(t *testing.T) {
	auditor := &GroupAuditor{}
	if got := auditor.ResourceType(); got != "group" {
		t.Errorf("ResourceType() = %q, want %q", got, "group")
	}
}

func TestGroupAuditor_Check_ExemptName(t *testing.T) {
	auditor := &GroupAuditor{}
	g := groups.Group{ID: "grp-123", Name: "admins"}

	rule := &policy.Rule{
		Name:  "find-old-groups",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"admins"}},
	}

	result, err := auditor.Check(context.Background(), g, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt group")
	}
}

func TestGroupAuditor_Check_InvalidType(t *testing.T) {
	auditor := &GroupAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-group", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestGroupAuditor_Fix_Log(t *testing.T) {
	auditor := &GroupAuditor{}
	g := groups.Group{ID: "grp-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, g, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestGroupAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &GroupAuditor{}
	g := groups.Group{ID: "grp-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, g, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestGroupAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &GroupAuditor{}
	g := groups.Group{ID: "grp-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, g, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
