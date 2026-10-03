package heat

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type snapshotAdapter struct {
	s discoveryservices.HeatSnapshot
}

func (a snapshotAdapter) GetID() string {
	return a.s.StackName + "@" + a.s.SnapshotTime.Format(time.RFC3339)
}
func (a snapshotAdapter) GetName() string         { return a.s.StackName }
func (a snapshotAdapter) GetProjectID() string    { return "" }
func (a snapshotAdapter) GetStatus() string       { return "" } // heat snapshots have no state
func (a snapshotAdapter) GetCreatedAt() time.Time { return a.s.SnapshotTime }
func (a snapshotAdapter) GetUpdatedAt() time.Time { return a.s.SnapshotTime }

// SnapshotAuditor audits heat/snapshot resources (stack snapshots).
//
// Allowed checks: age_gt, exempt_names
// Allowed actions: log
//
// Note: the Heat snapshots API only exposes snapshot_time (no state and no
// timestamps beyond the capture time), so age_gt and exempt_names apply.
// The Heat API does not provide a delete-snapshot endpoint, so only log is
// offered as an action.
type SnapshotAuditor struct{}

func (a *SnapshotAuditor) ResourceType() string {
	return "snapshot"
}

func (a *SnapshotAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *SnapshotAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(discoveryservices.HeatSnapshot)
	if !ok {
		return nil, fmt.Errorf("expected discovery services HeatSnapshot, got %T", resource)
	}

	adapter := snapshotAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *SnapshotAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	switch rule.Action {
	case "log":
		return nil
	default:
		return fmt.Errorf("heat/snapshot: action %q not implemented (the Heat API has no delete-snapshot endpoint)", rule.Action)
	}
}
