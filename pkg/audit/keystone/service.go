package keystone

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/services"
)

type serviceAdapter struct{ s services.Service }

func (a serviceAdapter) GetID() string { return a.s.ID }

// GetName returns the service's catalog name from Extra["name"] when
// present, falling back to its Type (e.g. "compute", "volumev3") since
// keystone's v3 Service has no dedicated Name field.
func (a serviceAdapter) GetName() string {
	if name, ok := a.s.Extra["name"].(string); ok && name != "" {
		return name
	}
	return a.s.Type
}
func (a serviceAdapter) GetProjectID() string { return "" } // the catalog is not project-scoped

// GetStatus derives a status string from Enabled, since keystone's v3
// Service has no status field of its own.
func (a serviceAdapter) GetStatus() string {
	if a.s.Enabled {
		return "enabled"
	}
	return "disabled"
}
func (a serviceAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a serviceAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// ServiceAuditor audits keystone/service resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: keystone's v3 Service has no timestamp fields, so age_gt is
// accepted for policy consistency but is a no-op. Determining whether a
// catalog service has any registered endpoints requires a separate API
// call, which Check() cannot do without a client, so unused is left as a
// pending observation.
type ServiceAuditor struct{}

func (a *ServiceAuditor) ResourceType() string {
	return "service"
}

func (a *ServiceAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *ServiceAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(services.Service)
	if !ok {
		return nil, fmt.Errorf("expected services.Service, got %T", resource)
	}

	adapter := serviceAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && !s.Enabled {
		result.Compliant = false
		result.Observation = "service is disabled"
	}

	return result, nil
}

func (a *ServiceAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	s, ok := resource.(services.Service)
	if !ok {
		return fmt.Errorf("expected services.Service, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := services.Delete(c, s.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting service %s: %w", s.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/service: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/service: action %q not implemented", rule.Action)
	}
}
