package magnum

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

type clusterAdapter struct {
	c discoveryservices.MagnumCluster
}

func (a clusterAdapter) GetID() string           { return a.c.ID }
func (a clusterAdapter) GetName() string         { return a.c.Name }
func (a clusterAdapter) GetProjectID() string    { return "" } // the list endpoint does not return the project
func (a clusterAdapter) GetStatus() string       { return a.c.Status }
func (a clusterAdapter) GetCreatedAt() time.Time { return a.c.CreatedAt }
func (a clusterAdapter) GetUpdatedAt() time.Time { return a.c.UpdatedAt }

// ClusterAuditor audits magnum/cluster resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete
//
// Note: clusters expose no "in use" signal, so unused is not offered.
type ClusterAuditor struct{}

func (a *ClusterAuditor) ResourceType() string {
	return "cluster"
}

func (a *ClusterAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ClusterAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	c, ok := resource.(discoveryservices.MagnumCluster)
	if !ok {
		return nil, fmt.Errorf("expected discovery services MagnumCluster, got %T", resource)
	}

	adapter := clusterAdapter{c: c}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *ClusterAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	cluster, ok := resource.(discoveryservices.MagnumCluster)
	if !ok {
		return fmt.Errorf("expected discovery services MagnumCluster, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		resp, err := c.Request("DELETE", c.ServiceURL("clusters", cluster.ID), &gophercloud.RequestOpts{
			OkCodes: []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		})
		if err != nil {
			return fmt.Errorf("deleting cluster %s: %w", cluster.Name, err)
		}
		defer resp.Body.Close()
		return nil

	default:
		return fmt.Errorf("magnum/cluster: action %q not implemented", rule.Action)
	}
}
