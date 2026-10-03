package manila

import (
	"context"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type ShareAuditor struct{}
func (a *ShareAuditor) ResourceType() string { return "share" }
func (a *ShareAuditor) ImplementedChecks() []string { return []string{"status","age_gt","unused","exempt_names"} }
func (a *ShareAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ShareAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error { return nil }

type ShareSnapshotAuditor struct{}
func (a *ShareSnapshotAuditor) ResourceType() string { return "share_snapshot" }
func (a *ShareSnapshotAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *ShareSnapshotAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ShareSnapshotAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error { return nil }

type ShareNetworkAuditor struct{}
func (a *ShareNetworkAuditor) ResourceType() string { return "share_network" }
func (a *ShareNetworkAuditor) ImplementedChecks() []string { return []string{"age_gt","exempt_names"} }
func (a *ShareNetworkAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ShareNetworkAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error { return nil }

type ShareServerAuditor struct{}
func (a *ShareServerAuditor) ResourceType() string { return "share_server" }
func (a *ShareServerAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *ShareServerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ShareServerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error { return nil }
