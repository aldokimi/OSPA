package ironic

import (
	"context"
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/drivers"
)

// DriverAuditor audits ironic/driver resources.
//
// Allowed checks: exempt_names
// Allowed actions: log
//
// Note: drivers are installed hardware driver definitions (e.g. "ipmi",
// "redfish"), not deletable resources - gophercloud's drivers package has
// no Delete function because ironic exposes none. There is also no status
// or timestamp field.
type DriverAuditor struct{}

func (a *DriverAuditor) ResourceType() string {
	return "driver"
}

func (a *DriverAuditor) ImplementedChecks() []string {
	return []string{"exempt_names"}
}

func (a *DriverAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	d, ok := resource.(drivers.Driver)
	if !ok {
		return nil, fmt.Errorf("expected drivers.Driver, got %T", resource)
	}

	result := &audit.Result{
		RuleID:       rule.Name,
		ResourceID:   d.Name,
		ResourceName: d.Name,
		Compliant:    true,
		Rule:         rule,
	}

	for _, pattern := range rule.Check.ExemptNames {
		if d.Name == pattern {
			result.Observation = "exempt by name"
			return result, nil
		}
	}

	return result, nil
}

func (a *DriverAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	if rule.Action == "log" {
		return nil
	}

	return fmt.Errorf("ironic/driver: action %q not supported (drivers have no delete API)", rule.Action)
}
