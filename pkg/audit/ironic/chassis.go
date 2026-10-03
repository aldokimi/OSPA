package ironic

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

type chassisAdapter struct{ c discoveryservices.Chassis }

func (a chassisAdapter) GetID() string           { return a.c.UUID }
func (a chassisAdapter) GetName() string         { return a.c.Description } // chassis have no name, only a free-form description
func (a chassisAdapter) GetProjectID() string    { return "" }              // ironic chassis are not project-scoped
func (a chassisAdapter) GetStatus() string       { return "" }              // chassis have no status
func (a chassisAdapter) GetCreatedAt() time.Time { return a.c.CreatedAt }
func (a chassisAdapter) GetUpdatedAt() time.Time { return a.c.UpdatedAt }

// ChassisAuditor audits ironic/chassis resources.
//
// Allowed checks: age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: gophercloud has no typed package for this legacy, optional ironic
// resource (see discoveryservices.Chassis); Fix() issues a raw DELETE
// against the same REST endpoint discovery reads from.
type ChassisAuditor struct{}

func (a *ChassisAuditor) ResourceType() string {
	return "chassis"
}

func (a *ChassisAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *ChassisAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	c, ok := resource.(discoveryservices.Chassis)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.Chassis, got %T", resource)
	}

	adapter := chassisAdapter{c: c}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *ChassisAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	ch, ok := resource.(discoveryservices.Chassis)
	if !ok {
		return fmt.Errorf("expected discoveryservices.Chassis, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		url := c.ServiceURL("chassis", ch.UUID)
		if _, err := c.Delete(url, nil); err != nil {
			return fmt.Errorf("deleting chassis %s: %w", ch.UUID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("ironic/chassis: tag action not yet implemented")

	default:
		return fmt.Errorf("ironic/chassis: action %q not implemented", rule.Action)
	}
}
