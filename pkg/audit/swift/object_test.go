package swift

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
)

func TestObjectAuditor_ResourceType(t *testing.T) {
	auditor := &ObjectAuditor{}
	if got := auditor.ResourceType(); got != "object" {
		t.Errorf("ResourceType() = %q, want %q", got, "object")
	}
}

func TestObjectAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ObjectAuditor{}
	o := discoveryservices.ObjectWithContainer{
		Object:        objects.Object{Name: "keep.txt"},
		ContainerName: "bucket-1",
	}

	rule := &policy.Rule{
		Name:  "find-old-objects",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"keep.txt"}},
	}

	result, err := auditor.Check(context.Background(), o, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt object")
	}
	if result.ResourceID != "bucket-1/keep.txt" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "bucket-1/keep.txt")
	}
}

func TestObjectAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ObjectAuditor{}

	_, err := auditor.Check(context.Background(), "not-an-object", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestObjectAuditor_Fix_Log(t *testing.T) {
	auditor := &ObjectAuditor{}
	o := discoveryservices.ObjectWithContainer{Object: objects.Object{Name: "f.txt"}, ContainerName: "bucket-1"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestObjectAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ObjectAuditor{}
	o := discoveryservices.ObjectWithContainer{Object: objects.Object{Name: "f.txt"}, ContainerName: "bucket-1"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestObjectAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ObjectAuditor{}
	o := discoveryservices.ObjectWithContainer{Object: objects.Object{Name: "f.txt"}, ContainerName: "bucket-1"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, o, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
