package designate

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
)

type recordAdapter struct{ r discoveryservices.Record }

func (a recordAdapter) GetID() string           { return a.r.RecordSetID + "/" + a.r.Value }
func (a recordAdapter) GetName() string         { return a.r.Name }
func (a recordAdapter) GetProjectID() string    { return "" } // not carried on the decomposed Record type
func (a recordAdapter) GetStatus() string       { return a.r.Status }
func (a recordAdapter) GetCreatedAt() time.Time { return a.r.CreatedAt }
func (a recordAdapter) GetUpdatedAt() time.Time { return a.r.UpdatedAt }

// RecordAuditor audits designate/record resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: Designate has no standalone "record" API. Each record is one value
// within its parent recordset's Records list (see discoveryservices.Record).
// Fix("delete") re-fetches the parent recordset and updates it with the
// value removed; when the record was the recordset's last value the
// recordset is deleted instead, since a Designate recordset cannot hold
// zero records and an empty Update would be a silent no-op (the records
// field is omitempty in the PATCH body).
type RecordAuditor struct{}

func (a *RecordAuditor) ResourceType() string {
	return "record"
}

func (a *RecordAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *RecordAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	r, ok := resource.(discoveryservices.Record)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.Record, got %T", resource)
	}

	adapter := recordAdapter{r: r}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *RecordAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	r, ok := resource.(discoveryservices.Record)
	if !ok {
		return fmt.Errorf("expected discoveryservices.Record, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		rs, err := recordsets.Get(c, r.ZoneID, r.RecordSetID).Extract()
		if err != nil {
			return fmt.Errorf("fetching recordset %s in zone %s: %w", r.RecordSetID, r.ZoneID, err)
		}

		remaining := make([]string, 0, len(rs.Records))
		for _, v := range rs.Records {
			if v != r.Value {
				remaining = append(remaining, v)
			}
		}

		if len(remaining) == 0 {
			// Last value: an Update with an empty Records slice is omitted
			// from the PATCH body (omitempty) and would be a no-op. Delete
			// the now-empty recordset instead.
			if err := recordsets.Delete(c, r.ZoneID, r.RecordSetID).ExtractErr(); err != nil {
				return fmt.Errorf("deleting recordset %s in zone %s (last record removed): %w", r.RecordSetID, r.ZoneID, err)
			}
			return nil
		}

		opts := recordsets.UpdateOpts{Records: remaining}
		if _, err := recordsets.Update(c, r.ZoneID, r.RecordSetID, opts).Extract(); err != nil {
			return fmt.Errorf("removing record %s from recordset %s: %w", r.Value, r.RecordSetID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("designate/record: tag action not yet implemented")

	default:
		return fmt.Errorf("designate/record: action %q not implemented", rule.Action)
	}
}
