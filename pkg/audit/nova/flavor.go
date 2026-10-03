package nova

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
)

type flavorAdapter struct{ f flavors.Flavor }

func (a flavorAdapter) GetID() string           { return a.f.ID }
func (a flavorAdapter) GetName() string         { return a.f.Name }
func (a flavorAdapter) GetProjectID() string    { return "" } // flavors are global, not project-scoped
func (a flavorAdapter) GetStatus() string       { return "" } // flavors have no status
func (a flavorAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a flavorAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// FlavorAuditor audits nova/flavor resources.
//
// Allowed checks: exempt_names, is_public
// Allowed actions: log, delete, tag
//
// Note: gophercloud's flavors.Flavor has no status or timestamp fields, so
// only exempt_names and the flavor-specific is_public check are meaningful.
type FlavorAuditor struct{}

func (a *FlavorAuditor) ResourceType() string {
	return "flavor"
}

func (a *FlavorAuditor) ImplementedChecks() []string {
	return []string{"exempt_names", "is_public"}
}

func (a *FlavorAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	f, ok := resource.(flavors.Flavor)
	if !ok {
		return nil, fmt.Errorf("expected flavors.Flavor, got %T", resource)
	}

	adapter := flavorAdapter{f: f}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	if rule.Check.IsPublic != nil && f.IsPublic != *rule.Check.IsPublic {
		result.Compliant = false
		result.Observation = fmt.Sprintf("flavor is_public is %t", f.IsPublic)
	}

	return result, nil
}

func (a *FlavorAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	f, ok := resource.(flavors.Flavor)
	if !ok {
		return fmt.Errorf("expected flavors.Flavor, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := flavors.Delete(c, f.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting flavor %s: %w", f.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("nova/flavor: tag action not yet implemented")

	default:
		return fmt.Errorf("nova/flavor: action %q not implemented", rule.Action)
	}
}
