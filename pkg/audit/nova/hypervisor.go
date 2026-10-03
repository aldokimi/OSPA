package nova

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/hypervisors"
)

type hypervisorAdapter struct{ h hypervisors.Hypervisor }

func (a hypervisorAdapter) GetID() string        { return a.h.ID }
func (a hypervisorAdapter) GetName() string      { return a.h.HypervisorHostname }
func (a hypervisorAdapter) GetProjectID() string { return "" } // hypervisors are host-level, not project-scoped

// GetStatus returns the hypervisor's State (up/down) rather than its Status
// (enabled/disabled admin toggle) — State reflects actual reachability,
// which is what a "status: down" policy check is meant to catch.
func (a hypervisorAdapter) GetStatus() string       { return a.h.State }
func (a hypervisorAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a hypervisorAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// HypervisorAuditor audits nova/hypervisor resources.
//
// Allowed checks: status, exempt_names
// Allowed actions: log
//
// Note: hypervisors are read-only from the compute API's perspective (there
// is no delete/tag call), so only the "log" action is supported; Fix()
// rejects delete/tag with a clear error.
type HypervisorAuditor struct{}

func (a *HypervisorAuditor) ResourceType() string {
	return "hypervisor"
}

func (a *HypervisorAuditor) ImplementedChecks() []string {
	return []string{"status", "exempt_names"}
}

func (a *HypervisorAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	h, ok := resource.(hypervisors.Hypervisor)
	if !ok {
		return nil, fmt.Errorf("expected hypervisors.Hypervisor, got %T", resource)
	}

	adapter := hypervisorAdapter{h: h}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	common.CheckStatus(adapter, rule, result)

	return result, nil
}

func (a *HypervisorAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	if rule.Action == "log" {
		return nil
	}

	return fmt.Errorf("nova/hypervisor: action %q not supported (hypervisors are read-only)", rule.Action)
}
