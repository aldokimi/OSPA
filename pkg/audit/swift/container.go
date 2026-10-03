package swift

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
)

type containerAdapter struct{ c containers.Container }

func (a containerAdapter) GetID() string           { return a.c.Name }
func (a containerAdapter) GetName() string         { return a.c.Name }
func (a containerAdapter) GetProjectID() string    { return "" } // already scoped to the authenticated project
func (a containerAdapter) GetStatus() string       { return "" } // containers have no status
func (a containerAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a containerAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// ContainerAuditor audits swift/container resources.
//
// Allowed checks: unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: gophercloud's Container listing struct has no status or timestamp
// fields, so only unused (empty container) and exempt_names apply.
type ContainerAuditor struct{}

func (a *ContainerAuditor) ResourceType() string {
	return "container"
}

func (a *ContainerAuditor) ImplementedChecks() []string {
	return []string{"unused", "exempt_names"}
}

func (a *ContainerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	c, ok := resource.(containers.Container)
	if !ok {
		return nil, fmt.Errorf("expected containers.Container, got %T", resource)
	}

	adapter := containerAdapter{c: c}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	if rule.Check.Unused && c.Count == 0 {
		result.Compliant = false
		result.Observation = "container is empty"
	}

	return result, nil
}

func (a *ContainerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	container, ok := resource.(containers.Container)
	if !ok {
		return fmt.Errorf("expected containers.Container, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if container.Count > 0 {
			return fmt.Errorf("cannot delete container %s: not empty (%d objects)", container.Name, container.Count)
		}
		if res := containers.Delete(c, container.Name); res.Err != nil {
			return fmt.Errorf("deleting container %s: %w", container.Name, res.Err)
		}
		return nil

	case "tag":
		return fmt.Errorf("swift/container: tag action not yet implemented")

	default:
		return fmt.Errorf("swift/container: action %q not implemented", rule.Action)
	}
}
