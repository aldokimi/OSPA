package glance

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Glance cross-resource composite patterns.
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "glance" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := glanceCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "public_image_cross_tenant_exposure":
		return a.checkPublicImageCrossTenant(resources, result)
	case "":
		return nil, fmt.Errorf("glance composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("glance composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("glance composite: action %q not implemented", rule.Action)
}

func glanceCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["public_image_cross_tenant_exposure"].(bool); ok && v {
		return "public_image_cross_tenant_exposure"
	}
	return ""
}

func (a *CompositeAuditor) checkPublicImageCrossTenant(
	resources map[string][]discovery.Job,
	result *audit.Result,
) (*audit.Result, error) {
	membersByImage := map[string][]members.Member{}
	for _, job := range resources["member"] {
		m, ok := job.Resource.(members.Member)
		if !ok {
			continue
		}
		membersByImage[m.ImageID] = append(membersByImage[m.ImageID], m)
	}

	for _, job := range resources["image"] {
		img, ok := job.Resource.(images.Image)
		if !ok {
			continue
		}
		vis := string(img.Visibility)
		if !strings.EqualFold(vis, "public") && !strings.EqualFold(vis, "shared") {
			continue
		}
		ms := membersByImage[img.ID]
		if strings.EqualFold(vis, "public") {
			// Public images are cross-tenant by definition; include member extras if present.
			result.Compliant = false
			result.ResourceID = img.ID
			result.ResourceName = img.Name
			result.ProjectID = img.Owner
			if len(ms) == 0 {
				result.Observation = fmt.Sprintf(
					"public_image_cross_tenant_exposure: image %q visibility=public (no member shares)",
					img.Name,
				)
			} else {
				ids := make([]string, 0, len(ms))
				for _, m := range ms {
					ids = append(ids, m.MemberID)
				}
				result.Observation = fmt.Sprintf(
					"public_image_cross_tenant_exposure: image %q visibility=public with member projects %v",
					img.Name, ids,
				)
			}
			return result, nil
		}
		// shared + members → explicit cross-tenant share list
		if len(ms) > 0 {
			ids := make([]string, 0, len(ms))
			for _, m := range ms {
				ids = append(ids, fmt.Sprintf("%s(%s)", m.MemberID, m.Status))
			}
			result.Compliant = false
			result.ResourceID = img.ID
			result.ResourceName = img.Name
			result.ProjectID = img.Owner
			result.Observation = fmt.Sprintf(
				"public_image_cross_tenant_exposure: image %q visibility=shared members=%v",
				img.Name, ids,
			)
			return result, nil
		}
	}

	result.Observation = "public_image_cross_tenant_exposure: no public/shared image exposure found"
	return result, nil
}
