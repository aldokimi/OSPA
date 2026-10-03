package magnum

import (
	"context"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

func TestClusterAuditor_ResourceType(t *testing.T) {
	auditor := &ClusterAuditor{}
	if got := auditor.ResourceType(); got != "cluster" {
		t.Errorf("ResourceType() = %q, want %q", got, "cluster")
	}
}

func TestClusterAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &ClusterAuditor{}
	c := discoveryservices.MagnumCluster{ID: "c1", Name: "k8s-cluster", Status: "CREATE_FAILED"}

	rule := &policy.Rule{
		Name:  "find-failed-clusters",
		Check: policy.CheckConditions{Status: "CREATE_FAILED"},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for matching status")
	}
	if result.ResourceID != "c1" {
		t.Errorf("Result.ResourceID = %q, want %q", result.ResourceID, "c1")
	}
}

func TestClusterAuditor_Check_StatusNoMatch(t *testing.T) {
	auditor := &ClusterAuditor{}
	c := discoveryservices.MagnumCluster{ID: "c1", Name: "k8s-cluster", Status: "CREATE_COMPLETE"}

	rule := &policy.Rule{
		Name:  "find-failed-clusters",
		Check: policy.CheckConditions{Status: "CREATE_FAILED"},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for non-matching status")
	}
}

func TestClusterAuditor_Check_AgeGT(t *testing.T) {
	auditor := &ClusterAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	c := discoveryservices.MagnumCluster{ID: "c1", Name: "old-cluster", Status: "CREATE_COMPLETE", CreatedAt: old}

	rule := &policy.Rule{
		Name:  "find-old-clusters",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for 60d-old cluster with age_gt 30d")
	}
}

func TestClusterAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ClusterAuditor{}
	c := discoveryservices.MagnumCluster{ID: "c1", Name: "system-cluster", Status: "CREATE_FAILED"}

	rule := &policy.Rule{
		Name: "find-failed-clusters",
		Check: policy.CheckConditions{
			Status:      "CREATE_FAILED",
			ExemptNames: []string{"system-*"},
		},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt name")
	}
}

func TestClusterAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ClusterAuditor{}
	rule := &policy.Rule{Name: "test", Check: policy.CheckConditions{}}
	if _, err := auditor.Check(context.Background(), "bogus", rule); err == nil {
		t.Error("Check() expected error for wrong resource type")
	}
}

func TestClusterAuditor_Fix_Log(t *testing.T) {
	auditor := &ClusterAuditor{}
	rule := &policy.Rule{Name: "test", Action: "log"}
	if err := auditor.Fix(context.Background(), nil, nil, rule); err != nil {
		t.Errorf("Fix(log) error = %v", err)
	}
}

func TestClusterAuditor_Fix_DeleteWrongResourceType(t *testing.T) {
	auditor := &ClusterAuditor{}
	rule := &policy.Rule{Name: "test", Action: "delete"}
	if err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, 42, rule); err == nil {
		t.Error("Fix(delete) expected error for wrong resource type")
	}
}

func TestClusterAuditor_Fix_TagNotImplemented(t *testing.T) {
	auditor := &ClusterAuditor{}
	rule := &policy.Rule{Name: "test", Action: "tag"}
	c := discoveryservices.MagnumCluster{ID: "c1", Name: "k8s-cluster"}
	if err := auditor.Fix(context.Background(), &gophercloud.ServiceClient{}, c, rule); err == nil {
		t.Error("Fix(tag) expected not-implemented error")
	}
}
