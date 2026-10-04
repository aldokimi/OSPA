package cinder

import (
	"context"
	"strings"
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

func TestQosAuditor_Check_QosConsumer(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{ID: "qos-1", Name: "limited", Consumer: "front-end"}

	rule := &policy.Rule{
		Name:  "require-back-end",
		Check: policy.CheckConditions{QosConsumer: "back-end"},
	}

	result, err := auditor.Check(context.Background(), q, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for consumer mismatch")
	}
}

func TestQosAuditor_Check_QosSpecKeys(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{
		ID:    "qos-2",
		Name:  "iops-limited",
		Specs: map[string]string{"total_iops_sec": "1000"},
	}

	rule := &policy.Rule{
		Name: "require-rate-limits",
		Check: policy.CheckConditions{
			QosSpecKeys: []string{"total_iops_sec", "total_bytes_sec"},
		},
	}

	result, err := auditor.Check(context.Background(), q, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for missing spec keys")
	}
	if result.Observation == "" {
		t.Fatal("expected observation for missing spec keys")
	}
}

func TestQosAuditor_Check_QosPostureGap(t *testing.T) {
	auditor := &QosAuditor{}
	q := qos.QoS{
		ID:       "qos-3",
		Name:     "weak",
		Consumer: "both",
		Specs:    map[string]string{},
	}

	rule := &policy.Rule{
		Name: "strict-qos",
		Check: policy.CheckConditions{
			QosConsumer: "back-end",
			QosSpecKeys: []string{"total_iops_sec"},
		},
	}

	result, err := auditor.Check(context.Background(), q, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant")
	}
	if !strings.Contains(result.Observation, "qos_posture_gap") {
		t.Fatalf("expected qos_posture_gap observation, got %q", result.Observation)
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
