package ironic

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/ports"
)

type portAdapter struct{ p ports.Port }

func (a portAdapter) GetID() string           { return a.p.UUID }
func (a portAdapter) GetName() string         { return a.p.Address } // ports have no display name; MAC address is the closest identifier
func (a portAdapter) GetProjectID() string    { return "" }          // ironic ports are not project-scoped
func (a portAdapter) GetStatus() string       { return "" }          // ports have no status field
func (a portAdapter) GetCreatedAt() time.Time { return a.p.CreatedAt }
func (a portAdapter) GetUpdatedAt() time.Time { return a.p.UpdatedAt }

// PortAuditor audits ironic/port resources.
//
// Allowed checks: age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: gophercloud's Port has no status field, and every port is required
// to belong to a node, so there is no meaningful "unused" signal to offer.
type PortAuditor struct{}

func (a *PortAuditor) ResourceType() string {
	return "port"
}

func (a *PortAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *PortAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	p, ok := resource.(ports.Port)
	if !ok {
		return nil, fmt.Errorf("expected ports.Port, got %T", resource)
	}

	adapter := portAdapter{p: p}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *PortAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	p, ok := resource.(ports.Port)
	if !ok {
		return fmt.Errorf("expected ports.Port, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := ports.Delete(c, p.UUID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting port %s: %w", p.UUID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("ironic/port: tag action not yet implemented")

	default:
		return fmt.Errorf("ironic/port: action %q not implemented", rule.Action)
	}
}
