package keystone

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
)

func TestProjectAuditor_ResourceType(t *testing.T) {
	auditor := &ProjectAuditor{}
	if got := auditor.ResourceType(); got != "project" {
		t.Errorf("ResourceType() = %q, want %q", got, "project")
	}
}

func TestProjectAuditor_Check_StatusDisabled(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123", Name: "test-project", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-projects",
		Check: policy.CheckConditions{Status: "disabled"},
	}

	result, err := auditor.Check(context.Background(), p, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for disabled project")
	}
	if result.ProjectID != "proj-123" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-123")
	}
}

func TestProjectAuditor_Check_Unused(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123", Name: "test-project", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-projects",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), p, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for disabled project")
	}
}

func TestProjectAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123", Name: "admin", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-projects",
		Check: policy.CheckConditions{Status: "disabled", ExemptNames: []string{"admin"}},
	}

	result, err := auditor.Check(context.Background(), p, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt project")
	}
}

func TestProjectAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ProjectAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-project", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestProjectAuditor_Fix_Log(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestProjectAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestProjectAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ProjectAuditor{}
	p := projects.Project{ID: "proj-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, p, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
