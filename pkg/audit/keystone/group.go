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
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

type groupAdapter struct{ g groups.Group }

func (a groupAdapter) GetID() string           { return a.g.ID }
func (a groupAdapter) GetName() string         { return a.g.Name }
func (a groupAdapter) GetProjectID() string    { return "" }
func (a groupAdapter) GetStatus() string       { return "" }
func (a groupAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a groupAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// GroupAuditor audits keystone/group resources.
//
// Allowed checks: age_gt, unused, exempt_names, mfa_enabled
// mfa_enabled and unused enumerate group members via the service client in
// context (audit.WithClient).
type GroupAuditor struct{}

func (a *GroupAuditor) ResourceType() string {
	return "group"
}

func (a *GroupAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "unused", "exempt_names", "mfa_enabled"}
}

func (a *GroupAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
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

	needsMembers := rule.Check.Unused || rule.Check.MFAEnabled != nil
	var members []users.User
	if needsMembers {
		members, err = listGroupUsers(ctx, g.ID)
		if err != nil {
			result.Observation = fmt.Sprintf("group relationship check failed: %v", err)
			return result, nil
		}
	}

	if rule.Check.Unused && len(members) == 0 {
		result.Compliant = false
		result.Observation = "group has no members"
	}

	if rule.Check.MFAEnabled != nil && *rule.Check.MFAEnabled {
		var withoutMFA []string
		for _, m := range members {
			if !userMFAEnabled(m) {
				withoutMFA = append(withoutMFA, m.Name)
			}
		}
		if len(withoutMFA) > 0 {
			result.Compliant = false
			result.Observation = fmt.Sprintf(
				"group_members_no_mfa: group %q has members without MFA: %v",
				g.Name, withoutMFA,
			)
		}
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
