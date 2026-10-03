package designate

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
)

func TestRecordsetAuditor_ResourceType(t *testing.T) {
	auditor := &RecordsetAuditor{}
	if got := auditor.ResourceType(); got != "recordset" {
		t.Errorf("ResourceType() = %q, want %q", got, "recordset")
	}
}

func TestRecordsetAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &RecordsetAuditor{}
	rs := recordsets.RecordSet{ID: "rs-123", Name: "www.example.com.", ZoneID: "zone-123", ProjectID: "proj-456", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-recordsets",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), rs, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR recordset")
	}
}

func TestRecordsetAuditor_Check_Unused(t *testing.T) {
	auditor := &RecordsetAuditor{}
	rs := recordsets.RecordSet{ID: "rs-123", Name: "www.example.com.", Records: []string{}}

	rule := &policy.Rule{
		Name:  "find-empty-recordsets",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), rs, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for empty recordset")
	}
}

func TestRecordsetAuditor_Check_InvalidType(t *testing.T) {
	auditor := &RecordsetAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-recordset", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestRecordsetAuditor_Fix_Log(t *testing.T) {
	auditor := &RecordsetAuditor{}
	rs := recordsets.RecordSet{ID: "rs-123", ZoneID: "zone-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, rs, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestRecordsetAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &RecordsetAuditor{}
	rs := recordsets.RecordSet{ID: "rs-123", ZoneID: "zone-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, rs, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestRecordsetAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &RecordsetAuditor{}
	rs := recordsets.RecordSet{ID: "rs-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, rs, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
