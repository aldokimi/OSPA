package barbican

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "barbican" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := barbicanCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "high_risk_stale_secret":
		return a.checkHighRiskStaleSecret(resources, rule, result)
	case "":
		return nil, fmt.Errorf("barbican composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("barbican composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("barbican composite: action %q not implemented", rule.Action)
}

func barbicanCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["high_risk_stale_secret"].(bool); ok && v {
		return "high_risk_stale_secret"
	}
	return ""
}

func (a *CompositeAuditor) checkHighRiskStaleSecret(
	resources map[string][]discovery.Job,
	rule *policy.CompositeRule,
	result *audit.Result,
) (*audit.Result, error) {
	ageStr, _ := rule.Check["age_gt"].(string)
	var maxAge time.Duration
	if ageStr != "" {
		cc := policy.CheckConditions{AgeGT: ageStr}
		d, err := cc.ParseAgeGT()
		if err != nil {
			return nil, fmt.Errorf("barbican composite rule %q: parsing age_gt: %w", rule.Name, err)
		}
		maxAge = d
	} else {
		maxAge = 24 * time.Hour
	}

	for _, job := range resources["secret"] {
		s, ok := job.Resource.(secrets.Secret)
		if !ok {
			continue
		}
		if classifySecretRisk(s.SecretType) != "high" {
			continue
		}
		ts := s.Updated
		if ts.IsZero() {
			ts = s.Created
		}
		if ts.IsZero() || time.Since(ts) <= maxAge {
			continue
		}

		result.Compliant = false
		result.ResourceID = discoveryservices.BarbicanRefID(s.SecretRef)
		result.ResourceName = s.Name
		result.Observation = fmt.Sprintf(
			"high_risk_stale_secret: secret_type=%q older than %s (last updated: %s)",
			s.SecretType, ageStr, ts.Format(time.RFC3339),
		)
		return result, nil
	}

	result.Observation = "high_risk_stale_secret: no stale high-risk secrets found"
	return result, nil
}
