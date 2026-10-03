package keystone

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
)

type roleAdapter struct{ r roles.Role }

func (a roleAdapter) GetID() string           { return a.r.ID }
func (a roleAdapter) GetName() string         { return a.r.Name }
func (a roleAdapter) GetProjectID() string    { return "" } // roles are global, not project-scoped
func (a roleAdapter) GetStatus() string       { return "" } // roles have no status
func (a roleAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a roleAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// RoleAuditor audits keystone/role resources.
//
// Allowed checks: age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: keystone's v3 Role has no timestamp fields, so age_gt is accepted
// for policy consistency but is a no-op. Determining whether a role is
// actually assigned to anyone requires enumerating role assignments, which
// Check() cannot do without a client, so unused is left as a pending
// observation.
type RoleAuditor struct{}

func (a *RoleAuditor) ResourceType() string {
	return "role"
}

func (a *RoleAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "unused", "exempt_names"}
}

func (a *RoleAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	r, ok := resource.(roles.Role)
	if !ok {
		return nil, fmt.Errorf("expected roles.Role, got %T", resource)
	}

	adapter := roleAdapter{r: r}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused {
		result.Observation = "unused check pending - requires role assignment enumeration"
	}

	return result, nil
}

func (a *RoleAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	r, ok := resource.(roles.Role)
	if !ok {
		return fmt.Errorf("expected roles.Role, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := roles.Delete(c, r.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting role %s: %w", r.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/role: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/role: action %q not implemented", rule.Action)
	}
}
