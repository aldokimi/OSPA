package barbican

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/containers"
)

type containerAdapter struct{ c containers.Container }

func (a containerAdapter) GetID() string           { return discoveryservices.BarbicanRefID(a.c.ContainerRef) }
func (a containerAdapter) GetName() string         { return a.c.Name }
func (a containerAdapter) GetProjectID() string    { return "" } // not exposed on the container resource itself
func (a containerAdapter) GetStatus() string       { return a.c.Status }
func (a containerAdapter) GetCreatedAt() time.Time { return a.c.Created }
func (a containerAdapter) GetUpdatedAt() time.Time { return a.c.Updated }

// ContainerAuditor audits barbican/container resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
type ContainerAuditor struct{}

func (a *ContainerAuditor) ResourceType() string {
	return "container"
}

func (a *ContainerAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *ContainerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	c, ok := resource.(containers.Container)
	if !ok {
		return nil, fmt.Errorf("expected containers.Container, got %T", resource)
	}

	adapter := containerAdapter{c: c}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && len(c.SecretRefs) == 0 {
		result.Compliant = false
		result.Observation = "container has no secret references"
	}

	return result, nil
}

func (a *ContainerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	cl, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	c, ok := resource.(containers.Container)
	if !ok {
		return fmt.Errorf("expected containers.Container, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		id := discoveryservices.BarbicanRefID(c.ContainerRef)
		if err := containers.Delete(cl, id).ExtractErr(); err != nil {
			return fmt.Errorf("deleting container %s: %w", id, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("barbican/container: tag action not yet implemented")

	default:
		return fmt.Errorf("barbican/container: action %q not implemented", rule.Action)
	}
}
