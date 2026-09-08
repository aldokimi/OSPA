package designate

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
)

type zoneAdapter struct{ z zones.Zone }

func (a zoneAdapter) GetID() string           { return a.z.ID }
func (a zoneAdapter) GetName() string         { return a.z.Name }
func (a zoneAdapter) GetProjectID() string    { return a.z.ProjectID }
func (a zoneAdapter) GetStatus() string       { return a.z.Status }
func (a zoneAdapter) GetCreatedAt() time.Time { return a.z.CreatedAt }
func (a zoneAdapter) GetUpdatedAt() time.Time { return a.z.UpdatedAt }

// ZoneAuditor audits designate/zone resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
type ZoneAuditor struct{}

func (a *ZoneAuditor) ResourceType() string {
	return "zone"
}

func (a *ZoneAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *ZoneAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	z, ok := resource.(zones.Zone)
	if !ok {
		return nil, fmt.Errorf("expected zones.Zone, got %T", resource)
	}

	adapter := zoneAdapter{z: z}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused {
		result.Observation = "unused check pending - requires recordset enumeration"
	}

	return result, nil
}

func (a *ZoneAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	z, ok := resource.(zones.Zone)
	if !ok {
		return fmt.Errorf("expected zones.Zone, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if res := zones.Delete(c, z.ID); res.Err != nil {
			return fmt.Errorf("deleting zone %s: %w", z.ID, res.Err)
		}
		return nil

	case "tag":
		return fmt.Errorf("designate/zone: tag action not yet implemented")

	default:
		return fmt.Errorf("designate/zone: action %q not implemented", rule.Action)
	}
}
