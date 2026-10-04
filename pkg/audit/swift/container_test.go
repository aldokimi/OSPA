package swift

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
)

func TestContainerAuditor_ResourceType(t *testing.T) {
	auditor := &ContainerAuditor{}
	if got := auditor.ResourceType(); got != "container" {
		t.Errorf("ResourceType() = %q, want %q", got, "container")
	}
}

func TestContainerAuditor_Check_Unused(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := discoveryservices.ContainerWithACL{Container: containers.Container{Name: "empty-bucket", Count: 0}}

	rule := &policy.Rule{
		Name:  "find-empty-containers",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for empty container")
	}
}

func TestContainerAuditor_Check_IsPublic(t *testing.T) {
	auditor := &ContainerAuditor{}
	wantPublic := false
	c := discoveryservices.ContainerWithACL{
		Container: containers.Container{Name: "public-bucket", Count: 1},
		ReadACL:   []string{".r:*,.rlistings"},
	}

	rule := &policy.Rule{
		Name:  "find-public-containers",
		Check: policy.CheckConditions{IsPublic: &wantPublic},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for world-readable container when is_public: false")
	}
}

func TestContainerAuditor_Check_PublicWrite(t *testing.T) {
	auditor := &ContainerAuditor{}
	wantWrite := false
	c := discoveryservices.ContainerWithACL{
		Container: containers.Container{Name: "open-bucket", Count: 1},
		WriteACL:  []string{".w:*"},
	}

	rule := &policy.Rule{
		Name:  "no-public-write",
		Check: policy.CheckConditions{PublicWrite: &wantWrite},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for world-writable container")
	}
}

func TestContainerAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ContainerAuditor{}
	c := discoveryservices.ContainerWithACL{Container: containers.Container{Name: "default", Count: 0}}

	rule := &policy.Rule{
		Name:  "find-empty-containers",
		Check: policy.CheckConditions{Unused: true, ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), c, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt container")
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
	c := discoveryservices.ContainerWithACL{Container: containers.Container{Name: "bucket-1"}}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, c, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}
