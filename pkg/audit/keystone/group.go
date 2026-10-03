package keystone

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
)

type groupAdapter struct{ g groups.Group }

func (a groupAdapter) GetID() string           { return a.g.ID }
func (a groupAdapter) GetName() string         { return a.g.Name }
func (a groupAdapter) GetProjectID() string    { return "" } // groups are not project-scoped
func (a groupAdapter) GetStatus() string       { return "" } // groups have no status
func (a groupAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a groupAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// GroupAuditor audits keystone/group resources.
//
// Allowed checks: age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: keystone's v3 Group has no timestamp or status fields, so age_gt
// is accepted for policy consistency but is a no-op. Determining whether a
// group has any members requires a separate API call per group, which
// Check() cannot do without a client, so unused is left as a pending
// observation.
type GroupAuditor struct{}

func (a *GroupAuditor) ResourceType() string {
	return "group"
}

func (a *GroupAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "unused", "exempt_names"}
}

func (a *GroupAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	g, ok := resource.(groups.Group)
	if !ok {
		return nil, fmt.Errorf("expected groups.Group, got %T", resource)
	}

	adapter := groupAdapter{g: g}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused {
		result.Observation = "unused check pending - requires group member enumeration"
	}

	return result, nil
}

func (a *GroupAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	g, ok := resource.(groups.Group)
	if !ok {
		return fmt.Errorf("expected groups.Group, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := groups.Delete(c, g.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting group %s: %w", g.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/group: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/group: action %q not implemented", rule.Action)
	}
}
