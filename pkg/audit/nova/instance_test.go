package nova

import (
	"context"
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

func TestInstanceAuditor_ResourceType(t *testing.T) {
	auditor := &InstanceAuditor{}
	if got := auditor.ResourceType(); got != "instance" {
		t.Errorf("ResourceType() = %q, want %q", got, "instance")
	}
}

func TestInstanceAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123", Name: "test-instance", TenantID: "proj-456", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-instances",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR instance")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestInstanceAuditor_Check_Unused_Shutoff(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123", Name: "stopped", Status: "SHUTOFF"}

	rule := &policy.Rule{
		Name:  "find-stopped-instances",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for SHUTOFF instance")
	}
}

func TestInstanceAuditor_Check_ImageName(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{
		ID:     "srv-123",
		Name:   "test-instance",
		Status: "ACTIVE",
		Image:  map[string]interface{}{"id": "banned-image-id"},
	}

	rule := &policy.Rule{
		Name:  "find-banned-images",
		Check: policy.CheckConditions{ImageName: []string{"banned-image-id"}},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for banned image")
	}
}

func TestInstanceAuditor_Check_NoKeypair(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123", Name: "test-instance", Status: "ACTIVE", KeyName: ""}

	rule := &policy.Rule{
		Name:  "find-instances-without-keypair",
		Check: policy.CheckConditions{NoKeypair: true},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for instance without keypair")
	}
}

func TestInstanceAuditor_Check_IdleNoKeypair(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123", Name: "idle", Status: "SHUTOFF", KeyName: ""}

	rule := &policy.Rule{
		Name:  "idle-no-keypair",
		Check: policy.CheckConditions{Unused: true, NoKeypair: true},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for SHUTOFF instance without keypair")
	}
	if !strings.Contains(result.Observation, "idle_no_keypair") {
		t.Fatalf("expected idle_no_keypair observation, got %q", result.Observation)
	}
}

func TestInstanceAuditor_Check_ExemptName(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123", Name: "default", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-instances",
		Check: policy.CheckConditions{Status: "ERROR", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt instance")
	}
}

func TestInstanceAuditor_Check_InvalidType(t *testing.T) {
	auditor := &InstanceAuditor{}

	_, err := auditor.Check(context.Background(), "not-an-instance", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestInstanceAuditor_Fix_Log(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestInstanceAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestInstanceAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &InstanceAuditor{}
	s := servers.Server{ID: "srv-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
