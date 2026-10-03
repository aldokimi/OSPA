package magnum

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

func TestBayModelAuditor_ResourceType(t *testing.T) {
	auditor := &BayModelAuditor{}
	if got := auditor.ResourceType(); got != "baymodel" {
		t.Errorf("ResourceType() = %q, want %q", got, "baymodel")
	}
}

func TestBayModelAuditor_Check_AgeGT(t *testing.T) {
	auditor := &BayModelAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	m := discoveryservices.MagnumBayModel{ID: "m1", Name: "worker-model", CreatedAt: old}

	rule := &policy.Rule{
		Name:  "find-old-models",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), m, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 60d-old model with age_gt 30d")
	}
	if result.ResourceID != "m1" {
		t.Errorf("Result.ResourceID = %q, want %q", result.ResourceID, "m1")
	}
}

func TestBayModelAuditor_Check_ExemptName(t *testing.T) {
	auditor := &BayModelAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	m := discoveryservices.MagnumBayModel{ID: "m1", Name: "system-model", CreatedAt: old}

	rule := &policy.Rule{
		Name: "find-old-models",
		Check: policy.CheckConditions{
			AgeGT:       "30d",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), m, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestBayModelAuditor_Check_InvalidType(t *testing.T) {
	auditor := &BayModelAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), 42, rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestBayModelAuditor_Fix_Log(t *testing.T) {
	auditor := &BayModelAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestBayModelAuditor_Fix_TagNotImplemented(t *testing.T) {
	auditor := &BayModelAuditor{}
	rule := &policy.Rule{Name: "test", Action: "tag"}
	m := discoveryservices.MagnumBayModel{ID: "m1", Name: "worker-model"}
	if err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, m, rule); err == nil {
		t.Error("Fix(tag) expected not-implemented error")
	}
}
