package heat

import (
	"context"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacks"
)

func TestStackAuditor_ResourceType(t *testing.T) {
	auditor := &StackAuditor{}
	if got := auditor.ResourceType(); got != "stack" {
		t.Errorf("ResourceType() = %q, want %q", got, "stack")
	}
}

func TestStackAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &StackAuditor{}
	s := stacks.ListedStack{ID: "s1", Name: "web-stack", Status: "CREATE_FAILED"}

	rule := &policy.Rule{
		Name:  "find-failed-stacks",
		Check: policy.CheckConditions{Status: "CREATE_FAILED"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for matching status")
	}
}

func TestStackAuditor_Check_StatusNoMatch(t *testing.T) {
	auditor := &StackAuditor{}
	s := stacks.ListedStack{ID: "s1", Name: "web-stack", Status: "CREATE_COMPLETE"}

	rule := &policy.Rule{
		Name:  "find-failed-stacks",
		Check: policy.CheckConditions{Status: "CREATE_FAILED"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for non-matching status")
	}
}

func TestStackAuditor_Check_AgeGT(t *testing.T) {
	auditor := &StackAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	s := stacks.ListedStack{ID: "s1", Name: "old-stack", Status: "CREATE_COMPLETE", CreationTime: old}

	rule := &policy.Rule{
		Name:  "find-old-stacks",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 60d-old stack with age_gt 30d")
	}
}

func TestStackAuditor_Check_ExemptName(t *testing.T) {
	auditor := &StackAuditor{}
	s := stacks.ListedStack{ID: "s1", Name: "system-stack", Status: "CREATE_FAILED"}

	rule := &policy.Rule{
		Name: "find-failed-stacks",
		Check: policy.CheckConditions{
			Status:      "CREATE_FAILED",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestStackAuditor_Check_InvalidType(t *testing.T) {
	auditor := &StackAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), "bogus", rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestStackAuditor_Fix_Log(t *testing.T) {
	auditor := &StackAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestStackAuditor_Fix_TagNotImplemented(t *testing.T) {
	auditor := &StackAuditor{}
	rule := &policy.Rule{Name: "test", Action: "tag"}
	s := stacks.ListedStack{ID: "s1", Name: "web-stack"}
	err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, s, rule)
	if err == nil {
		t.Error("Fix(tag) expected not-yet-implemented error")
	}
}
