package barbican

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/containers"
)

func TestContainerAuditor_ResourceType(t *testing.T) {
	auditor := &ContainerAuditor{}
	if got := auditor.ResourceType(); got != "container" {
		t.Errorf("ResourceType() = %q, want %q", got, "container")
	}
}

func TestContainerAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := containers.Container{ContainerRef: "https://kms/v1/containers/abc-123", Name: "tls-bundle", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-containers",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR container")
	}
	if result.ResourceID != "abc-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "abc-123")
	}
}

func TestContainerAuditor_Check_Unused(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := containers.Container{ContainerRef: "https://kms/v1/containers/abc-123", Name: "empty-bundle"}

	rule := &policy.Rule{
		Name:  "find-empty-containers",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for container with no secret refs")
	}
}

func TestContainerAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ContainerAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-container", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestContainerAuditor_Fix_Log(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := containers.Container{ContainerRef: "https://kms/v1/containers/abc-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestContainerAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := containers.Container{ContainerRef: "https://kms/v1/containers/abc-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestContainerAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := containers.Container{ContainerRef: "https://kms/v1/containers/abc-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
