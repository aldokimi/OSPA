package ironic

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/nodes"
)

func TestNodeAuditor_ResourceType(t *testing.T) {
	auditor := &NodeAuditor{}
	if got := auditor.ResourceType(); got != "node" {
		t.Errorf("ResourceType() = %q, want %q", got, "node")
	}
}

func TestNodeAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123", Name: "compute-01", ProvisionState: "error"}

	rule := &policy.Rule{
		Name:  "find-error-nodes",
		Check: policy.CheckConditions{Status: "error"},
	}

	result, err := auditor.Check(context.Background(), n, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for error node")
	}
}

func TestNodeAuditor_Check_Unused(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123", Name: "compute-01", InstanceUUID: ""}

	rule := &policy.Rule{
		Name:  "find-idle-nodes",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), n, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for node with no instance")
	}
}

func TestNodeAuditor_Check_ExemptName(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123", Name: "default", ProvisionState: "error"}

	rule := &policy.Rule{
		Name:  "find-error-nodes",
		Check: policy.CheckConditions{Status: "error", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), n, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt node")
	}
}

func TestNodeAuditor_Check_InvalidType(t *testing.T) {
	auditor := &NodeAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-node", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestNodeAuditor_Fix_Log(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, n, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestNodeAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, n, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestNodeAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &NodeAuditor{}
	n := nodes.Node{UUID: "node-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, n, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
