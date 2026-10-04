package neutron

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
)

// SecurityGroupRuleAuditor audits neutron/security_group_rule resources.
//
// Allowed checks: direction, ethertype, protocol, port, remote_ip_prefix,
// port_range_wide, exempt_names
// Allowed actions: log, delete
//
// Semantic outcomes (#102): when atomic criteria match a world-open rule on a
// sensitive port/protocol, observations use public_sensitive_service_exposure
// wording. When the policy does not pin a direction, observations escalate to
// bidirectional_world_exposure (true peer-rule composites live in CompositeAuditor).
type SecurityGroupRuleAuditor struct{}

const (
	worldIPv4CIDR     = "0.0.0.0/0"
	worldIPv6CIDR     = "::/0"
	portRangeWideSpan = 100
)

var sensitivePortProtocols = map[string]struct{}{
	"tcp:22":   {}, // ssh
	"tcp:3389": {}, // rdp
}

func (a *SecurityGroupRuleAuditor) ResourceType() string {
	return "security_group_rule"
}

func (a *SecurityGroupRuleAuditor) ImplementedChecks() []string {
	return []string{"direction", "ethertype", "protocol", "port", "remote_ip_prefix", "port_range_wide", "exempt_names"}
}

func (a *SecurityGroupRuleAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	sgRule, ok := resource.(rules.SecGroupRule)
	if !ok {
		return nil, fmt.Errorf("expected rules.SecGroupRule, got %T", resource)
	}

	ruleName := buildRuleName(sgRule)

	result := &audit.Result{
		RuleID:       rule.Name,
		ResourceID:   sgRule.ID,
		ResourceName: ruleName,
		ProjectID:    sgRule.TenantID,
		Status:       "ACTIVE",
		Compliant:    true,
		Rule:         rule,
	}

	if isExemptByName(sgRule.SecGroupID, rule.Check.ExemptNames) {
		result.Compliant = true
		result.Observation = "exempt by security group ID pattern"
		return result, nil
	}

	// Atomic AND matching: all specified checks must match for non-compliance.
	allChecksMatch := true
	var observations []string

	if rule.Check.Direction != "" {
		if sgRule.Direction != rule.Check.Direction {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("direction=%s", sgRule.Direction))
		}
	}

	if rule.Check.Ethertype != "" {
		if sgRule.EtherType != rule.Check.Ethertype {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("ethertype=%s", sgRule.EtherType))
		}
	}

	if rule.Check.Protocol != "" {
		if sgRule.Protocol != rule.Check.Protocol {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("protocol=%s", sgRule.Protocol))
		}
	}

	if rule.Check.Port != 0 {
		if !portMatches(sgRule.PortRangeMin, sgRule.PortRangeMax, rule.Check.Port) {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("port=%d (range %d-%d)", rule.Check.Port, sgRule.PortRangeMin, sgRule.PortRangeMax))
		}
	}

	if rule.Check.RemoteIPPrefix != "" {
		if sgRule.RemoteIPPrefix != rule.Check.RemoteIPPrefix {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("remote_ip_prefix=%s", sgRule.RemoteIPPrefix))
		}
	}

	if rule.Check.PortRangeWide {
		if !isPortRangeWide(sgRule.PortRangeMin, sgRule.PortRangeMax) {
			allChecksMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("port_range_wide=%d-%d", sgRule.PortRangeMin, sgRule.PortRangeMax))
		}
	}

	if allChecksMatch && len(observations) > 0 {
		result.Compliant = false
		result.Observation = semanticObservation(sgRule, rule.Check, observations)
	}

	return result, nil
}

func (a *SecurityGroupRuleAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	sgRule, ok := resource.(rules.SecGroupRule)
	if !ok {
		return fmt.Errorf("expected rules.SecGroupRule, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := rules.Delete(c, sgRule.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting security group rule %s: %w", sgRule.ID, err)
		}
		return nil

	default:
		return fmt.Errorf("neutron/security_group_rule: action %q not implemented", rule.Action)
	}
}

func isWorldExposure(prefix string) bool {
	return prefix == worldIPv4CIDR || prefix == worldIPv6CIDR
}

func isSensitivePortProtocol(protocol string, port int) bool {
	if protocol == "" || port <= 0 {
		return false
	}
	_, ok := sensitivePortProtocols[fmt.Sprintf("%s:%d", strings.ToLower(protocol), port)]
	return ok
}

func isPortRangeWide(min, max int) bool {
	if min == 0 && max == 0 {
		// All ports — treat as wider than the threshold.
		return true
	}
	if max < min {
		return false
	}
	return (max - min) > portRangeWideSpan
}

// semanticObservation upgrades atomic match text when the matched rule is a
// world-open sensitive service exposure (catalog: public_sensitive_service_exposure).
func semanticObservation(sg rules.SecGroupRule, check policy.CheckConditions, atomic []string) string {
	base := fmt.Sprintf("rule matches policy criteria: %v", atomic)

	port := check.Port
	if port == 0 && sg.PortRangeMin == sg.PortRangeMax && sg.PortRangeMin > 0 {
		port = sg.PortRangeMin
	}
	proto := check.Protocol
	if proto == "" {
		proto = sg.Protocol
	}

	world := isWorldExposure(sg.RemoteIPPrefix) &&
		(check.RemoteIPPrefix == "" || isWorldExposure(check.RemoteIPPrefix))
	sensitive := isSensitivePortProtocol(proto, port)

	if !world || !sensitive {
		return base
	}

	dir := sg.Direction
	if dir == "" {
		dir = "unknown"
	}

	// Direction omitted in policy ≈ evaluating any direction; label as
	// bidirectional escalation candidate (full peer-rule composite is #103/#107).
	if check.Direction == "" {
		return fmt.Sprintf(
			"bidirectional_world_exposure: world exposure for sensitive service %s/%d present (direction=%s); %s",
			proto, port, dir, base,
		)
	}

	return fmt.Sprintf(
		"public_sensitive_service_exposure: world exposure detected (%s/%s:%d); %s",
		dir, proto, port, base,
	)
}

func buildRuleName(r rules.SecGroupRule) string {
	proto := r.Protocol
	if proto == "" {
		proto = "any"
	}

	portRange := ""
	if r.PortRangeMin > 0 || r.PortRangeMax > 0 {
		if r.PortRangeMin == r.PortRangeMax {
			portRange = fmt.Sprintf(":%d", r.PortRangeMin)
		} else {
			portRange = fmt.Sprintf(":%d-%d", r.PortRangeMin, r.PortRangeMax)
		}
	}

	remote := r.RemoteIPPrefix
	if remote == "" && r.RemoteGroupID != "" {
		remote = fmt.Sprintf("sg:%s", r.RemoteGroupID)
	}
	if remote == "" {
		remote = "any"
	}

	return fmt.Sprintf("%s/%s%s from %s", r.Direction, proto, portRange, remote)
}

func portMatches(min, max, port int) bool {
	if min == 0 && max == 0 {
		return true
	}
	return port >= min && port <= max
}
