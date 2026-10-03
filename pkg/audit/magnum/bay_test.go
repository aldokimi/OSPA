package magnum

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

func TestBayAuditor_ResourceType(t *testing.T) {
	auditor := &BayAuditor{}
	if got := auditor.ResourceType(); got != "bay" {
		t.Errorf("ResourceType() = %q, want %q", got, "bay")
	}
}

func TestBayAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &BayAuditor{}
	b := discoveryservices.MagnumBay{ID: "b1", Name: "worker-bay", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-bays",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for matching status")
	}
	if result.ResourceID != "b1" {
		t.Errorf("Result.ResourceID = %q, want %q", result.ResourceID, "b1")
	}
}

func TestBayAuditor_Check_StatusNoMatch(t *testing.T) {
	auditor := &BayAuditor{}
	b := discoveryservices.MagnumBay{ID: "b1", Name: "worker-bay", Status: "DEFAULT"}

	rule := &policy.Rule{
		Name:  "find-error-bays",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for non-matching status")
	}
}

func TestBayAuditor_Check_AgeGT(t *testing.T) {
	auditor := &BayAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	b := discoveryservices.MagnumBay{ID: "b1", Name: "old-bay", Status: "DEFAULT", CreatedAt: old}

	rule := &policy.Rule{
		Name:  "find-old-bays",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 60d-old bay with age_gt 30d")
	}
}

func TestBayAuditor_Check_ExemptName(t *testing.T) {
	auditor := &BayAuditor{}
	b := discoveryservices.MagnumBay{ID: "b1", Name: "system-bay", Status: "ERROR"}

	rule := &policy.Rule{
		Name: "find-error-bays",
		Check: policy.CheckConditions{
			Status:      "ERROR",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestBayAuditor_Check_InvalidType(t *testing.T) {
	auditor := &BayAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), "bogus", rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestBayAuditor_Fix_Log(t *testing.T) {
	auditor := &BayAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestBayAuditor_Fix_TagNotImplemented(t *testing.T) {
	auditor := &BayAuditor{}
	rule := &policy.Rule{Name: "test", Action: "tag"}
	b := discoveryservices.MagnumBay{ID: "b1", Name: "worker-bay"}
	if err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, b, rule); err == nil {
		t.Error("Fix(tag) expected not-implemented error")
	}
}
