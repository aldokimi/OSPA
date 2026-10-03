package designate

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
)

type recordsetAdapter struct{ rs recordsets.RecordSet }

func (a recordsetAdapter) GetID() string           { return a.rs.ID }
func (a recordsetAdapter) GetName() string         { return a.rs.Name }
func (a recordsetAdapter) GetProjectID() string    { return a.rs.ProjectID }
func (a recordsetAdapter) GetStatus() string       { return a.rs.Status }
func (a recordsetAdapter) GetCreatedAt() time.Time { return a.rs.CreatedAt }
func (a recordsetAdapter) GetUpdatedAt() time.Time { return a.rs.UpdatedAt }

// RecordsetAuditor audits designate/recordset resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
type RecordsetAuditor struct{}

func (a *RecordsetAuditor) ResourceType() string {
	return "recordset"
}

func (a *RecordsetAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *RecordsetAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	rs, ok := resource.(recordsets.RecordSet)
	if !ok {
		return nil, fmt.Errorf("expected recordsets.RecordSet, got %T", resource)
	}

	adapter := recordsetAdapter{rs: rs}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && len(rs.Records) == 0 {
		result.Compliant = false
		result.Observation = "recordset has no records"
	}

	return result, nil
}

func (a *RecordsetAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	rs, ok := resource.(recordsets.RecordSet)
	if !ok {
		return fmt.Errorf("expected recordsets.RecordSet, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := recordsets.Delete(c, rs.ZoneID, rs.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting recordset %s in zone %s: %w", rs.ID, rs.ZoneID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("designate/recordset: tag action not yet implemented")

	default:
		return fmt.Errorf("designate/recordset: action %q not implemented", rule.Action)
	}
}
