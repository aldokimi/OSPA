package octavia

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Octavia cross-resource composite patterns.
//
// Supported check.pattern values:
//   - insecure_public_listener — LB with a world-open listener lacking TLS termination
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "octavia" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := compositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "insecure_public_listener":
		return a.checkInsecurePublicListener(resources, rule, result)
	case "":
		return nil, fmt.Errorf("octavia composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("octavia composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("octavia composite: action %q not implemented", rule.Action)
}

func compositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["insecure_public_listener"].(bool); ok && v {
		return "insecure_public_listener"
	}
	return ""
}

func (a *CompositeAuditor) checkInsecurePublicListener(
	resources map[string][]discovery.Job,
	rule *policy.CompositeRule,
	result *audit.Result,
) (*audit.Result, error) {
	_ = rule

	lbs := map[string]loadbalancers.LoadBalancer{}
	for _, job := range resources["loadbalancer"] {
		lb, ok := job.Resource.(loadbalancers.LoadBalancer)
		if !ok {
			continue
		}
		lbs[lb.ID] = lb
	}

	type hit struct {
		lb       loadbalancers.LoadBalancer
		listener listeners.Listener
	}
	var hits []hit

	for _, job := range resources["listener"] {
		l, ok := job.Resource.(listeners.Listener)
		if !ok {
			continue
		}
		if !isWorldOpenListener(l) || !isInsecureListener(l) {
			continue
		}
		for _, ref := range l.Loadbalancers {
			if lb, ok := lbs[ref.ID]; ok {
				hits = append(hits, hit{lb: lb, listener: l})
				break
			}
		}
	}

	if len(hits) == 0 {
		return result, nil
	}

	result.Compliant = false
	h := hits[0]
	result.ResourceID = h.listener.ID
	result.ResourceName = h.listener.Name
	result.ProjectID = h.listener.ProjectID
	result.Observation = fmt.Sprintf(
		"insecure_public_listener: lb=%s vip=%s listener=%s protocol=%s port=%d tls_container=%q hits=%d",
		h.lb.ID, h.lb.VipAddress, h.listener.ID, h.listener.Protocol, h.listener.ProtocolPort,
		h.listener.DefaultTlsContainerRef, len(hits),
	)
	return result, nil
}

func isWorldOpenListener(l listeners.Listener) bool {
	if len(l.AllowedCIDRs) == 0 {
		return true
	}
	for _, cidr := range l.AllowedCIDRs {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return true
		}
	}
	return false
}

func isInsecureListener(l listeners.Listener) bool {
	proto := strings.ToUpper(l.Protocol)
	switch proto {
	case "HTTP":
		return true
	case "TCP", "UDP", "SCTP":
		return l.ProtocolPort == 443 || l.ProtocolPort == 80
	case "TERMINATED_HTTPS", "HTTPS":
		return l.DefaultTlsContainerRef == ""
	default:
		return false
	}
}
