package heat

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacks"
)

type stackAdapter struct{ s stacks.ListedStack }

func (a stackAdapter) GetID() string           { return a.s.ID }
func (a stackAdapter) GetName() string         { return a.s.Name }
func (a stackAdapter) GetProjectID() string    { return "" } // the list endpoint does not return tenant_id
func (a stackAdapter) GetStatus() string       { return a.s.Status }
func (a stackAdapter) GetCreatedAt() time.Time { return a.s.CreationTime }
func (a stackAdapter) GetUpdatedAt() time.Time { return a.s.UpdatedTime }

// StackAuditor audits heat/stack resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete
//
// Note: heat stacks have no "in use" signal (usage depends on the deployed
// resources), so unused is not offered.
type StackAuditor struct{}

func (a *StackAuditor) ResourceType() string {
	return "stack"
}

func (a *StackAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *StackAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(stacks.ListedStack)
	if !ok {
		return nil, fmt.Errorf("expected stacks.ListedStack, got %T", resource)
	}

	adapter := stackAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *StackAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	s, ok := resource.(stacks.ListedStack)
	if !ok {
		return fmt.Errorf("expected stacks.ListedStack, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := stacks.Delete(c, s.Name, s.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting stack %s: %w", s.Name, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("heat/stack: tag action not yet implemented")

	default:
		return fmt.Errorf("heat/stack: action %q not implemented", rule.Action)
	}
}
