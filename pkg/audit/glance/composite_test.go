package glance

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

func TestGlanceComposite_Registered(t *testing.T) {
	if _, ok := audit.GetComposite("glance"); !ok {
		t.Fatal("expected glance CompositeAuditor")
	}
}

func TestGlanceComposite_PublicImage(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"image": {{
			Resource: images.Image{ID: "img-1", Name: "cirros", Visibility: images.ImageVisibilityPublic, Owner: "proj"},
		}},
		"member": {},
	}
	rule := &policy.CompositeRule{
		Name:      "public-exposure",
		Resources: []string{"image", "member"},
		Check:     map[string]interface{}{"pattern": "public_image_cross_tenant_exposure"},
	}
	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant || !strings.Contains(result.Observation, "public_image_cross_tenant_exposure") {
		t.Fatalf("unexpected result: compliant=%v obs=%q", result.Compliant, result.Observation)
	}
}

func TestGlanceComposite_SharedWithMembers(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"image": {{
			Resource: images.Image{ID: "img-1", Name: "private-share", Visibility: images.ImageVisibilityShared, Owner: "proj"},
		}},
		"member": {{
			Resource: members.Member{ImageID: "img-1", MemberID: "other-proj", Status: "accepted"},
		}},
	}
	rule := &policy.CompositeRule{
		Name:  "shared-exposure",
		Check: map[string]interface{}{"public_image_cross_tenant_exposure": true},
	}
	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant || !strings.Contains(result.Observation, "other-proj") {
		t.Fatalf("unexpected result: compliant=%v obs=%q", result.Compliant, result.Observation)
	}
}
