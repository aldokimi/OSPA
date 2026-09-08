package keystone

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
)

func TestRoleAuditor_ResourceType(t *testing.T) {
	auditor := &RoleAuditor{}
	if got := auditor.ResourceType(); got != "role" {
		t.Errorf("ResourceType() = %q, want %q", got, "role")
	}
}

func TestRoleAuditor_Check_ExemptName(t *testing.T) {
	auditor := &RoleAuditor{}
	r := roles.Role{ID: "role-123", Name: "admin"}

	rule := &policy.Rule{
		Name:  "find-old-roles",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"admin"}},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt role")
	}
}

func TestRoleAuditor_Check_AgeGT_NoOp(t *testing.T) {
	auditor := &RoleAuditor{}
	r := roles.Role{ID: "role-123", Name: "custom-role"}

	rule := &policy.Rule{
		Name:  "find-old-roles",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant (age_gt is a no-op without timestamps)")
	}
}

func TestRoleAuditor_Check_InvalidType(t *testing.T) {
	auditor := &RoleAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-role", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestRoleAuditor_Fix_Log(t *testing.T) {
	auditor := &RoleAuditor{}
	r := roles.Role{ID: "role-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestRoleAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &RoleAuditor{}
	r := roles.Role{ID: "role-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestRoleAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &RoleAuditor{}
	r := roles.Role{ID: "role-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
