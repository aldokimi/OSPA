package manila

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type shareAdapter struct{ s discoveryservices.ManilaShare }

func (a shareAdapter) GetID() string           { return a.s.ID }
func (a shareAdapter) GetName() string         { return a.s.Name }
func (a shareAdapter) GetProjectID() string    { return a.s.ProjectID }
func (a shareAdapter) GetStatus() string       { return a.s.Status }
func (a shareAdapter) GetCreatedAt() time.Time { return a.s.CreatedAt }
func (a shareAdapter) GetUpdatedAt() time.Time { return a.s.UpdatedAt }

// ShareAuditor audits manila/share resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, is_public
// Encryption-at-rest/in-transit fields are not exposed on the share API;
// document as API-audit model availability gap.
type ShareAuditor struct{}

func (a *ShareAuditor) ResourceType() string { return "share" }

func (a *ShareAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "is_public"}
}

func (a *ShareAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	s, ok := resource.(discoveryservices.ManilaShare)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ManilaShare, got %T", resource)
	}

	adapter := shareAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && s.Status == "available" {
		result.Compliant = false
		result.Observation = "share is available (unused)"
	}

	if rule.Check.IsPublic != nil && s.IsPublic != *rule.Check.IsPublic {
		result.Compliant = false
		result.Observation = fmt.Sprintf("share is_public is %t", s.IsPublic)
	}

	return result, nil
}

func (a *ShareAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("manila/share: action %q not implemented", rule.Action)
}

type shareSnapshotAdapter struct{ s discoveryservices.ManilaShareSnapshot }

func (a shareSnapshotAdapter) GetID() string           { return a.s.ID }
func (a shareSnapshotAdapter) GetName() string         { return a.s.Name }
func (a shareSnapshotAdapter) GetProjectID() string    { return a.s.ProjectID }
func (a shareSnapshotAdapter) GetStatus() string       { return a.s.Status }
func (a shareSnapshotAdapter) GetCreatedAt() time.Time { return a.s.CreatedAt }
func (a shareSnapshotAdapter) GetUpdatedAt() time.Time { return a.s.UpdatedAt }

type ShareSnapshotAuditor struct{}

func (a *ShareSnapshotAuditor) ResourceType() string { return "share_snapshot" }
func (a *ShareSnapshotAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ShareSnapshotAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	s, ok := resource.(discoveryservices.ManilaShareSnapshot)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ManilaShareSnapshot, got %T", resource)
	}
	adapter := shareSnapshotAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *ShareSnapshotAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("manila/share_snapshot: action %q not implemented", rule.Action)
}

type shareNetworkAdapter struct{ n discoveryservices.ManilaShareNetwork }

func (a shareNetworkAdapter) GetID() string           { return a.n.ID }
func (a shareNetworkAdapter) GetName() string         { return a.n.Name }
func (a shareNetworkAdapter) GetProjectID() string    { return a.n.ProjectID }
func (a shareNetworkAdapter) GetStatus() string       { return "" }
func (a shareNetworkAdapter) GetCreatedAt() time.Time { return a.n.CreatedAt }
func (a shareNetworkAdapter) GetUpdatedAt() time.Time { return a.n.UpdatedAt }

type ShareNetworkAuditor struct{}

func (a *ShareNetworkAuditor) ResourceType() string { return "share_network" }
func (a *ShareNetworkAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *ShareNetworkAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	n, ok := resource.(discoveryservices.ManilaShareNetwork)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ManilaShareNetwork, got %T", resource)
	}
	adapter := shareNetworkAdapter{n: n}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}
	if err := common.CheckAgeGT(adapter, rule, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *ShareNetworkAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("manila/share_network: action %q not implemented", rule.Action)
}

type shareServerAdapter struct{ s discoveryservices.ManilaShareServer }

func (a shareServerAdapter) GetID() string           { return a.s.ID }
func (a shareServerAdapter) GetName() string         { return a.s.ID }
func (a shareServerAdapter) GetProjectID() string    { return a.s.ProjectID }
func (a shareServerAdapter) GetStatus() string       { return a.s.Status }
func (a shareServerAdapter) GetCreatedAt() time.Time { return a.s.CreatedAt }
func (a shareServerAdapter) GetUpdatedAt() time.Time { return a.s.UpdatedAt }

type ShareServerAuditor struct{}

func (a *ShareServerAuditor) ResourceType() string { return "share_server" }
func (a *ShareServerAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ShareServerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	s, ok := resource.(discoveryservices.ManilaShareServer)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ManilaShareServer, got %T", resource)
	}
	adapter := shareServerAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *ShareServerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("manila/share_server: action %q not implemented", rule.Action)
}
