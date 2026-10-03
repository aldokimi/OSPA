package ironic

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/baremetal/v1/nodes"
)

type nodeAdapter struct{ n nodes.Node }

func (a nodeAdapter) GetID() string           { return a.n.UUID }
func (a nodeAdapter) GetName() string         { return a.n.Name }
func (a nodeAdapter) GetProjectID() string    { return "" } // ironic nodes are not project-scoped
func (a nodeAdapter) GetStatus() string       { return a.n.ProvisionState }
func (a nodeAdapter) GetCreatedAt() time.Time { return a.n.CreatedAt }
func (a nodeAdapter) GetUpdatedAt() time.Time { return a.n.UpdatedAt }

// NodeAuditor audits ironic/node resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
type NodeAuditor struct{}

func (a *NodeAuditor) ResourceType() string {
	return "node"
}

func (a *NodeAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *NodeAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	n, ok := resource.(nodes.Node)
	if !ok {
		return nil, fmt.Errorf("expected nodes.Node, got %T", resource)
	}

	adapter := nodeAdapter{n: n}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && n.InstanceUUID == "" {
		result.Compliant = false
		result.Observation = "node has no instance deployed"
	}

	return result, nil
}

func (a *NodeAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	n, ok := resource.(nodes.Node)
	if !ok {
		return fmt.Errorf("expected nodes.Node, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if n.InstanceUUID != "" {
			return fmt.Errorf("cannot delete node %s: has a deployed instance (%s)", n.UUID, n.InstanceUUID)
		}
		if err := nodes.Delete(c, n.UUID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting node %s: %w", n.UUID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("ironic/node: tag action not yet implemented")

	default:
		return fmt.Errorf("ironic/node: action %q not implemented", rule.Action)
	}
}
