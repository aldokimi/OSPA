package neutron

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Neutron cross-resource composite patterns.
//
// Supported check.pattern values (see docs/reference/composite-patterns.md):
//   - shared_network_world_exposure
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "neutron" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := compositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "shared_network_world_exposure":
		return a.checkSharedNetworkWorldExposure(resources, rule, result)
	case "":
		return nil, fmt.Errorf("neutron composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("neutron composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("neutron composite: action %q not implemented", rule.Action)
}

func compositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	// Allow boolean shorthand: shared_network_world_exposure: true
	if v, ok := rule.Check["shared_network_world_exposure"].(bool); ok && v {
		return "shared_network_world_exposure"
	}
	return ""
}

func (a *CompositeAuditor) checkSharedNetworkWorldExposure(
	resources map[string][]discovery.Job,
	rule *policy.CompositeRule,
	result *audit.Result,
) (*audit.Result, error) {
	_ = rule

	sharedNets := map[string]networks.Network{}
	for _, job := range resources["network"] {
		n, ok := job.Resource.(networks.Network)
		if !ok || !n.Shared {
			continue
		}
		sharedNets[n.ID] = n
	}

	// SG IDs that have world-open rules.
	worldSGs := map[string]rules.SecGroupRule{}
	for _, job := range resources["security_group_rule"] {
		r, ok := job.Resource.(rules.SecGroupRule)
		if !ok {
			continue
		}
		if isWorldExposure(r.RemoteIPPrefix) {
			worldSGs[r.SecGroupID] = r
		}
	}

	type hit struct {
		network networks.Network
		port    ports.Port
		rule    rules.SecGroupRule
	}
	var hits []hit

	for _, job := range resources["port"] {
		p, ok := job.Resource.(ports.Port)
		if !ok {
			continue
		}
		net, shared := sharedNets[p.NetworkID]
		if !shared {
			continue
		}
		for _, sgID := range p.SecurityGroups {
			if r, ok := worldSGs[sgID]; ok {
				hits = append(hits, hit{network: net, port: p, rule: r})
				break
			}
		}
	}

	if len(hits) == 0 {
		result.Observation = "shared_network_world_exposure: no shared network with world-open SG rules"
		return result, nil
	}

	h := hits[0]
	result.Compliant = false
	result.ResourceID = h.network.ID
	result.ResourceName = h.network.Name
	result.ProjectID = h.network.ProjectID
	if result.ProjectID == "" {
		result.ProjectID = h.network.TenantID
	}
	result.Observation = fmt.Sprintf(
		"shared_network_world_exposure: shared network %q (%s) has port %s bound to SG with world-open rule %s (%d hit(s))",
		h.network.Name, h.network.ID, h.port.ID, h.rule.ID, len(hits),
	)
	return result, nil
}
