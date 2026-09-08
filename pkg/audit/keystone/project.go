package keystone

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
)

type projectAdapter struct{ p projects.Project }

func (a projectAdapter) GetID() string        { return a.p.ID }
func (a projectAdapter) GetName() string      { return a.p.Name }
func (a projectAdapter) GetProjectID() string { return a.p.ID }

// GetStatus derives a status string from Enabled, since keystone's v3
// Project has no status field of its own.
func (a projectAdapter) GetStatus() string {
	if a.p.Enabled {
		return "enabled"
	}
	return "disabled"
}
func (a projectAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a projectAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// ProjectAuditor audits keystone/project resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: keystone's v3 Project has no timestamp fields, so age_gt is
// accepted for policy consistency but is a no-op. Determining whether a
// project actually holds any resources requires enumerating every other
// service, which Check() cannot do, so unused is left as a pending
// observation.
type ProjectAuditor struct{}

func (a *ProjectAuditor) ResourceType() string {
	return "project"
}

func (a *ProjectAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *ProjectAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	p, ok := resource.(projects.Project)
	if !ok {
		return nil, fmt.Errorf("expected projects.Project, got %T", resource)
	}

	adapter := projectAdapter{p: p}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && !p.Enabled {
		result.Compliant = false
		result.Observation = "project is disabled"
	}

	return result, nil
}

func (a *ProjectAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	p, ok := resource.(projects.Project)
	if !ok {
		return fmt.Errorf("expected projects.Project, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := projects.Delete(c, p.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting project %s: %w", p.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/project: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/project: action %q not implemented", rule.Action)
	}
}
