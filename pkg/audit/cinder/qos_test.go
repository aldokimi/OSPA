package cinder

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/qos"
)

func TestQosAuditor_ResourceType(t *testing.T) {
	auditor := &QosAuditor{}
	if got := auditor.ResourceType(); got != "qos" {
		t.Errorf("ResourceType() = %q, want %q", got, "qos")
	}
}

func TestQosAuditor_Check_ExemptName(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-123", Name: "default"}

	rule := &policy.Rule{
		Name:  "find-qos-specs",
		Check: policy.CheckConditions{ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), q, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt qos spec")
	}
}

func TestQosAuditor_Check_NotExempt(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-123", Name: "custom-qos"}

	rule := &policy.Rule{
		Name:  "find-qos-specs",
		Check: policy.CheckConditions{ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), q, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant by default (no violation condition beyond exemption)")
	}
	if result.ResourceID != "qos-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "qos-123")
	}
}

func TestQosAuditor_Check_InvalidType(t *testing.T) {
	auditor := &QosAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-qos-spec", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestQosAuditor_Fix_Log(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, q, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestQosAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, q, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestQosAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, q, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
