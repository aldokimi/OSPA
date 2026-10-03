package magnum

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

func TestClusterTemplateAuditor_ResourceType(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	if got := auditor.ResourceType(); got != "cluster_template" {
		t.Errorf("ResourceType() = %q, want %q", got, "cluster_template")
	}
}

func TestClusterTemplateAuditor_Check_AgeGT(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	tmpl := discoveryservices.MagnumClusterTemplate{ID: "t1", Name: "ubuntu-k8s", CreatedAt: old}

	rule := &policy.Rule{
		Name:  "find-old-templates",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), tmpl, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 60d-old template with age_gt 30d")
	}
	if result.ResourceID != "t1" {
		t.Errorf("Result.ResourceID = %q, want %q", result.ResourceID, "t1")
	}
}

func TestClusterTemplateAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	tmpl := discoveryservices.MagnumClusterTemplate{ID: "t1", Name: "system-ubuntu", CreatedAt: old}

	rule := &policy.Rule{
		Name: "find-old-templates",
		Check: policy.CheckConditions{
			AgeGT:       "30d",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), tmpl, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestClusterTemplateAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), 3.14, rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestClusterTemplateAuditor_Fix_Log(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestClusterTemplateAuditor_Fix_TagNotImplemented(t *testing.T) {
	auditor := &ClusterTemplateAuditor{}
	rule := &policy.Rule{Name: "test", Action: "tag"}
	tmpl := discoveryservices.MagnumClusterTemplate{ID: "t1", Name: "ubuntu-k8s"}
	if err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, tmpl, rule); err == nil {
		t.Error("Fix(tag) expected not-implemented error")
	}
}
