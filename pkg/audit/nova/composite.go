package nova

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Nova cross-resource composite patterns.
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "nova" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := novaCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "public_flavor_network_binding":
		return a.checkPublicFlavorNetworkBinding(resources, result)
	case "":
		return nil, fmt.Errorf("nova composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("nova composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("nova composite: action %q not implemented", rule.Action)
}

func novaCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["public_flavor_network_binding"].(bool); ok && v {
		return "public_flavor_network_binding"
	}
	return ""
}

// checkPublicFlavorNetworkBinding flags instances that use a public flavor and
// have network addresses bound. Joining Neutron shared/external is a follow-up
// cross-service concern; Addresses presence is the Nova-local binding signal.
func (a *CompositeAuditor) checkPublicFlavorNetworkBinding(
	resources map[string][]discovery.Job,
	result *audit.Result,
) (*audit.Result, error) {
	publicFlavors := map[string]flavors.Flavor{}
	for _, job := range resources["flavor"] {
		f, ok := job.Resource.(flavors.Flavor)
		if !ok || !f.IsPublic {
			continue
		}
		publicFlavors[f.ID] = f
	}

	for _, job := range resources["instance"] {
		s, ok := job.Resource.(servers.Server)
		if !ok {
			continue
		}
		flavorID, _ := s.Flavor["id"].(string)
		f, isPublic := publicFlavors[flavorID]
		if !isPublic {
			continue
		}
		if len(s.Addresses) == 0 {
			continue
		}
		nets := make([]string, 0, len(s.Addresses))
		for name := range s.Addresses {
			nets = append(nets, name)
		}
		result.Compliant = false
		result.ResourceID = s.ID
		result.ResourceName = s.Name
		result.ProjectID = s.TenantID
		result.Observation = fmt.Sprintf(
			"public_flavor_network_binding: instance %q uses public flavor %q (%s) on networks %v",
			s.Name, f.Name, f.ID, nets,
		)
		return result, nil
	}

	result.Observation = "public_flavor_network_binding: no public-flavor instances with network bindings"
	return result, nil
}
