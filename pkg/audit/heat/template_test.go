package heat

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func TestTemplateAuditor_ResourceType(t *testing.T) {
	auditor := &TemplateAuditor{}
	if got := auditor.ResourceType(); got != "template" {
		t.Errorf("ResourceType() = %q, want %q", got, "template")
	}
}

func TestTemplateAuditor_Check_ExemptName(t *testing.T) {
	auditor := &TemplateAuditor{}
	tpl := discoveryservices.HeatTemplate{StackName: "system-base", StackID: "id-1"}

	rule := &policy.Rule{
		Name:  "exempt-system",
		Check: policy.CheckConditions{ExemptNames: []string{"system-*"}},
	}

	result, err := auditor.Check(context.Background(), tpl, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
	if result.Observation != "exempt by name" {
		t.Errorf("Observation = %q, want %q", result.Observation, "exempt by name")
	}
}

func TestTemplateAuditor_Check_CompliantByDefault(t *testing.T) {
	auditor := &TemplateAuditor{}
	tpl := discoveryservices.HeatTemplate{StackName: "web", StackID: "id-2"}

	rule := &policy.Rule{
		Name:  "no-op",
		Check: policy.CheckConditions{},
	}

	result, err := auditor.Check(context.Background(), tpl, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant by default")
	}
}

func TestTemplateAuditor_Check_InvalidType(t *testing.T) {
	auditor := &TemplateAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), "bogus", rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestTemplateAuditor_Fix_Log(t *testing.T) {
	auditor := &TemplateAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestTemplateAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &TemplateAuditor{}
	rule := &policy.Rule{Name: "test", Action: "delete"}
	tpl := discoveryservices.HeatTemplate{StackName: "web", StackID: "id-2"}
	if err := auditor.Fix(context.Background(), nil, tpl, rule); err == nil {
		t.Error("Fix(delete) expected not-supported error")
	}
}
