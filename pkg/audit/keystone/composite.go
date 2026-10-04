package keystone

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Keystone cross-resource relationship patterns.
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "keystone" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := keystoneCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "service_account_no_mfa":
		return a.checkServiceAccountNoMFA(resources, result)
	case "":
		return nil, fmt.Errorf("keystone composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("keystone composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("keystone composite: action %q not implemented", rule.Action)
}

func keystoneCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["service_account_no_mfa"].(bool); ok && v {
		return "service_account_no_mfa"
	}
	return ""
}

func (a *CompositeAuditor) checkServiceAccountNoMFA(
	resources map[string][]discovery.Job,
	result *audit.Result,
) (*audit.Result, error) {
	for _, job := range resources["user"] {
		u, ok := job.Resource.(users.User)
		if !ok || !userIsServiceAccount(u) {
			continue
		}
		if userMFAEnabled(u) {
			continue
		}
		result.Compliant = false
		result.ResourceID = u.ID
		result.ResourceName = u.Name
		result.Observation = fmt.Sprintf(
			"service_account_no_mfa: service user %q has MFA disabled",
			u.Name,
		)
		return result, nil
	}
	result.Observation = "service_account_no_mfa: no service users without MFA found"
	return result, nil
}
