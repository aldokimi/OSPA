package glance

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
)

func TestImageAuditor_ResourceType(t *testing.T) {
	auditor := &ImageAuditor{}
	if got := auditor.ResourceType(); got != "image" {
		t.Errorf("ResourceType() = %q, want %q", got, "image")
	}
}

func TestImageAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123", Name: "test-image", Owner: "proj-456", Status: images.ImageStatus("queued")}

	rule := &policy.Rule{
		Name:  "find-queued-images",
		Check: policy.CheckConditions{Status: "queued"},
	}

	result, err := auditor.Check(context.Background(), img, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for queued image")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestImageAuditor_Check_Visibility(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123", Name: "test-image", Visibility: images.ImageVisibility("public")}

	rule := &policy.Rule{
		Name:  "find-public-images",
		Check: policy.CheckConditions{Visibility: "public"},
	}

	result, err := auditor.Check(context.Background(), img, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for public image")
	}
}

func TestImageAuditor_Check_Unused_Hidden(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123", Name: "test-image", Hidden: true}

	rule := &policy.Rule{
		Name:  "find-hidden-images",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), img, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for hidden image")
	}
}

func TestImageAuditor_Check_ExemptName(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123", Name: "default", Visibility: images.ImageVisibility("public")}

	rule := &policy.Rule{
		Name:  "find-public-images",
		Check: policy.CheckConditions{Visibility: "public", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), img, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt image")
	}
}

func TestImageAuditor_Check_InvalidType(t *testing.T) {
	auditor := &ImageAuditor{}

	_, err := auditor.Check(context.Background(), "not-an-image", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestImageAuditor_Fix_Log(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, img, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestImageAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, img, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestImageAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &ImageAuditor{}
	img := images.Image{ID: "img-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, img, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
