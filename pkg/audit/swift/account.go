package swift

import (
	"context"
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/accounts"
)

// AccountAuditor audits the swift/account resource.
//
// Allowed checks: quota_set
// Allowed actions: log
//
// Note: an account is a singleton per authenticated project - there is no
// name, status, or delete API for it - so only the quota_set check and the
// log action apply.
type AccountAuditor struct{}

func (a *AccountAuditor) ResourceType() string {
	return "account"
}

func (a *AccountAuditor) ImplementedChecks() []string {
	return []string{"quota_set"}
}

func (a *AccountAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	h, ok := resource.(accounts.GetHeader)
	if !ok {
		return nil, fmt.Errorf("expected accounts.GetHeader, got %T", resource)
	}

	result := &audit.Result{
		RuleID:       rule.Name,
		ResourceID:   "account",
		ResourceName: "account",
		Compliant:    true,
		Rule:         rule,
	}

	if rule.Check.QuotaSet != nil {
		quotaSet := h.QuotaBytes != nil
		if quotaSet != *rule.Check.QuotaSet {
			result.Compliant = false
			result.Observation = fmt.Sprintf("account quota configured: %t", quotaSet)
		}
	}

	return result, nil
}

func (a *AccountAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	if rule.Action == "log" {
		return nil
	}

	return fmt.Errorf("swift/account: action %q not supported (account has no delete API)", rule.Action)
}
