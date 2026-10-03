package designate

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func TestRecordAuditor_ResourceType(t *testing.T) {
	auditor := &RecordAuditor{}
	if got := auditor.ResourceType(); got != "record" {
		t.Errorf("ResourceType() = %q, want %q", got, "record")
	}
}

func TestRecordAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &RecordAuditor{}
	r := discoveryservices.Record{
		ZoneID: "zone-123", RecordSetID: "rs-123",
		Name: "www.example.com.", Value: "10.0.0.1", Status: "ERROR",
	}

	rule := &policy.Rule{
		Name:  "find-error-records",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR record")
	}
	if result.ResourceID != "rs-123/10.0.0.1" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "rs-123/10.0.0.1")
	}
}

func TestRecordAuditor_Check_ExemptName(t *testing.T) {
	auditor := &RecordAuditor{}
	r := discoveryservices.Record{
		ZoneID: "zone-123", RecordSetID: "rs-123",
		Name: "www.example.com.", Value: "10.0.0.1", Status: "ERROR",
	}

	rule := &policy.Rule{
		Name:  "find-error-records",
		Check: policy.CheckConditions{Status: "ERROR", ExemptNames: []string{"www.example.com."}},
	}

	result, err := auditor.Check(context.Background(), r, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt record")
	}
}

func TestRecordAuditor_Check_InvalidType(t *testing.T) {
	auditor := &RecordAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-record", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestRecordAuditor_Fix_Log(t *testing.T) {
	auditor := &RecordAuditor{}
	r := discoveryservices.Record{ZoneID: "zone-123", RecordSetID: "rs-123", Value: "10.0.0.1"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestRecordAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &RecordAuditor{}
	r := discoveryservices.Record{ZoneID: "zone-123", RecordSetID: "rs-123", Value: "10.0.0.1"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestRecordAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &RecordAuditor{}
	r := discoveryservices.Record{ZoneID: "zone-123", RecordSetID: "rs-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, r, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
