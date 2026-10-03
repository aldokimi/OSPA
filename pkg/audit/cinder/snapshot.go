package cinder

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/snapshots"
)

type snapshotAdapter struct{ s snapshots.Snapshot }

func (a snapshotAdapter) GetID() string           { return a.s.ID }
func (a snapshotAdapter) GetName() string         { return a.s.Name }
func (a snapshotAdapter) GetProjectID() string    { return "" } // not exposed by the cinder v3 snapshots API
func (a snapshotAdapter) GetStatus() string       { return a.s.Status }
func (a snapshotAdapter) GetCreatedAt() time.Time { return a.s.CreatedAt }
func (a snapshotAdapter) GetUpdatedAt() time.Time { return a.s.UpdatedAt }

// SnapshotAuditor audits cinder/snapshot resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, encrypted
// Allowed actions: log, delete, tag
//
// Note: the cinder v3 snapshots API does not expose whether a snapshot is
// encrypted directly; it is inherited from the source volume, which is not
// available on the snapshot resource itself. The "encrypted" check is
// accepted for policy consistency but is a no-op until the source volume's
// encryption state is threaded through.
type SnapshotAuditor struct{}

func (a *SnapshotAuditor) ResourceType() string {
	return "snapshot"
}

func (a *SnapshotAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *SnapshotAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(snapshots.Snapshot)
	if !ok {
		return nil, fmt.Errorf("expected snapshots.Snapshot, got %T", resource)
	}

	adapter := snapshotAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused {
		result.Observation = "unused check pending - requires volume enumeration"
	}

	return result, nil
}

func (a *SnapshotAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	s, ok := resource.(snapshots.Snapshot)
	if !ok {
		return fmt.Errorf("expected snapshots.Snapshot, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := snapshots.Delete(c, s.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting snapshot %s: %w", s.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("cinder/snapshot: tag action not yet implemented")

	default:
		return fmt.Errorf("cinder/snapshot: action %q not implemented", rule.Action)
	}
}
