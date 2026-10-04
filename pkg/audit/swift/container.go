package swift

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
)

type containerAdapter struct{ c discoveryservices.ContainerWithACL }

func (a containerAdapter) GetID() string           { return a.c.Name }
func (a containerAdapter) GetName() string         { return a.c.Name }
func (a containerAdapter) GetProjectID() string    { return "" }
func (a containerAdapter) GetStatus() string       { return "" }
func (a containerAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a containerAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// ContainerAuditor audits swift/container resources.
//
// Allowed checks: unused, exempt_names, is_public, public_write
// Allowed actions: log, delete, tag
type ContainerAuditor struct{}

func (a *ContainerAuditor) ResourceType() string {
	return "container"
}

func (a *ContainerAuditor) ImplementedChecks() []string {
	return []string{"unused", "exempt_names", "is_public", "public_write"}
}

func (a *ContainerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	c, ok := resource.(discoveryservices.ContainerWithACL)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ContainerWithACL, got %T", resource)
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

	publicRead := discoveryservices.ACLAllowsWorldRead(c.ReadACL)
	if rule.Check.IsPublic != nil && publicRead != *rule.Check.IsPublic {
		result.Compliant = false
		result.Observation = fmt.Sprintf("container public read ACL is %t (read=%v)", publicRead, c.ReadACL)
	}

	publicWrite := discoveryservices.ACLAllowsWorldWrite(c.WriteACL)
	if rule.Check.PublicWrite != nil && publicWrite != *rule.Check.PublicWrite {
		result.Compliant = false
		result.Observation = fmt.Sprintf("container public write ACL is %t (write=%v)", publicWrite, c.WriteACL)
	}

	// #115 catalog outcome: world-readable and world-writable container.
	if publicRead && publicWrite && !result.Compliant {
		if rule.Check.IsPublic != nil && *rule.Check.IsPublic && rule.Check.PublicWrite != nil && *rule.Check.PublicWrite {
			result.Observation = fmt.Sprintf(
				"swift_container_world_exposure: read=%v write=%v",
				c.ReadACL, c.WriteACL,
			)
		}
	}

	return result, nil
}

func (a *ContainerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	svc, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	container, ok := resource.(discoveryservices.ContainerWithACL)
	if !ok {
		return fmt.Errorf("expected discoveryservices.ContainerWithACL, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if container.Count > 0 {
			return fmt.Errorf("cannot delete container %s: not empty (%d objects)", container.Name, container.Count)
		}
		if res := containers.Delete(svc, container.Name); res.Err != nil {
			return fmt.Errorf("deleting container %s: %w", container.Name, res.Err)
		}
		return nil

	case "tag":
		return fmt.Errorf("swift/container: tag action not yet implemented")

	default:
		return fmt.Errorf("swift/container: action %q not implemented", rule.Action)
	}
}
