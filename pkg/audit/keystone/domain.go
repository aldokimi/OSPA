package keystone

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/domains"
)

type domainAdapter struct{ d domains.Domain }

func (a domainAdapter) GetID() string        { return a.d.ID }
func (a domainAdapter) GetName() string      { return a.d.Name }
func (a domainAdapter) GetProjectID() string { return "" } // domains are not project-scoped

// GetStatus derives a status string from Enabled, since keystone's v3
// Domain has no status field of its own.
func (a domainAdapter) GetStatus() string {
	if a.d.Enabled {
		return "enabled"
	}
	return "disabled"
}
func (a domainAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a domainAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// DomainAuditor audits keystone/domain resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: keystone's v3 Domain has no timestamp fields, so age_gt is
// accepted for policy consistency but is a no-op. Determining whether a
// domain actually holds any projects/users requires further enumeration,
// which Check() cannot do, so unused is left as a pending observation.
type DomainAuditor struct{}

func (a *DomainAuditor) ResourceType() string {
	return "domain"
}

func (a *DomainAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *DomainAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	d, ok := resource.(domains.Domain)
	if !ok {
		return nil, fmt.Errorf("expected domains.Domain, got %T", resource)
	}

	adapter := domainAdapter{d: d}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && !d.Enabled {
		result.Compliant = false
		result.Observation = "domain is disabled"
	}

	return result, nil
}

func (a *DomainAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	d, ok := resource.(domains.Domain)
	if !ok {
		return fmt.Errorf("expected domains.Domain, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if d.Enabled {
			return fmt.Errorf("cannot delete domain %s: must be disabled first", d.ID)
		}
		if err := domains.Delete(c, d.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting domain %s: %w", d.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/domain: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/domain: action %q not implemented", rule.Action)
	}
}
