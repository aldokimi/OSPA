package designate

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
)

func TestZoneAuditor_ResourceType(t *testing.T) {
	auditor := &ZoneAuditor{}
	if got := auditor.ResourceType(); got != "zone" {
		t.Errorf("ResourceType() = %q, want %q", got, "zone")
	}
}

func TestZoneAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &ZoneAuditor{}
	z := zones.Zone{ID: "zone-123", Name: "example.com.", ProjectID: "proj-456", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-zones",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), z, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR zone")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestZoneAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ZoneAuditor{}
	z := zones.Zone{ID: "zone-123", Name: "default.com.", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-zones",
		Check: policy.CheckConditions{Status: "ERROR", ExemptNames: []string{"default.com."}},
	}

	result, err := auditor.Check(context.Background(), z, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt zone")
	}
}

func TestZoneAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ZoneAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-zone", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestZoneAuditor_Fix_Log(t *testing.T) {
	auditor := &ZoneAuditor{}
	z := zones.Zone{ID: "zone-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, z, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestZoneAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ZoneAuditor{}
	z := zones.Zone{ID: "zone-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, z, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestZoneAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ZoneAuditor{}
	z := zones.Zone{ID: "zone-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, z, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
