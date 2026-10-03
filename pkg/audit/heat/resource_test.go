package heat

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stackresources"
)

// heatResourceForTest builds a HeatResourceInStack for the given fields.
func heatResourceForTest(stack, name, status string) discoveryservices.HeatResourceInStack {
	return discoveryservices.HeatResourceInStack{
		Resource:  stackresources.Resource{Name: name, Status: status},
		StackName: stack,
	}
}

func TestResourceAuditor_ResourceType(t *testing.T) {
	auditor := &ResourceAuditor{}
	if got := auditor.ResourceType(); got != "resource" {
		t.Errorf("ResourceType() = %q, want %q", got, "resource")
	}
}

func TestResourceAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &ResourceAuditor{}
	r := heatResourceForTest("stack-a", "web_server", "CREATE_FAILED")

	rule := &policy.Rule{
		Name:  "find-failed-resources",
		Check: policy.CheckConditions{Status: "CREATE_FAILED"},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for matching status")
	}
	if result.ResourceID != "stack-a/web_server" {
		t.Errorf("Result.ResourceID = %q, want %q", result.ResourceID, "stack-a/web_server")
	}
}

func TestResourceAuditor_Check_AgeGT(t *testing.T) {
	auditor := &ResourceAuditor{}
	r := heatResourceForTest("stack-a", "db", "CREATE_COMPLETE")
	r.CreationTime = time.Now().Add(-90 * 24 * time.Hour)

	rule := &policy.Rule{
		Name:  "find-old-resources",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 90d-old resource with age_gt 30d")
	}
}

func TestResourceAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ResourceAuditor{}
	r := heatResourceForTest("stack-a", "system_db", "CREATE_FAILED")

	rule := &policy.Rule{
		Name: "find-failed-resources",
		Check: policy.CheckConditions{
			Status:      "CREATE_FAILED",
			ExemptNames: []string{"system_*"},
		},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestResourceAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ResourceAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), 42, rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestResourceAuditor_Fix_Log(t *testing.T) {
	auditor := &ResourceAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestResourceAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &ResourceAuditor{}
	rule := &policy.Rule{Name: "test", Action: "delete"}
	r := heatResourceForTest("stack-a", "web_server", "CREATE_COMPLETE")
	if err := auditor.Fix(context.Background(), nil, r, rule); err == nil {
		t.Error("Fix(delete) expected not-supported error")
	}
}
