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

type bayAdapter struct{ b discoveryservices.MagnumBay }

func (a bayAdapter) GetID() string           { return a.b.ID }
func (a bayAdapter) GetName() string         { return a.b.Name }
func (a bayAdapter) GetProjectID() string    { return "" } // the list endpoint does not return the project
func (a bayAdapter) GetStatus() string       { return a.b.Status }
func (a bayAdapter) GetCreatedAt() time.Time { return a.b.CreatedAt }
func (a bayAdapter) GetUpdatedAt() time.Time { return a.b.UpdatedAt }

// BayAuditor audits magnum/bay resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete
//
// Note: bays expose no "in use" signal, so unused is not offered.
type BayAuditor struct{}

func (a *BayAuditor) ResourceType() string {
	return "bay"
}

func (a *BayAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *BayAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	b, ok := resource.(discoveryservices.MagnumBay)
	if !ok {
		return nil, fmt.Errorf("expected discovery services MagnumBay, got %T", resource)
	}

	adapter := bayAdapter{b: b}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *BayAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	bay, ok := resource.(discoveryservices.MagnumBay)
	if !ok {
		return fmt.Errorf("expected discovery services MagnumBay, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		resp, err := c.Request("DELETE", c.ServiceURL("bays", bay.ID), &gophercloud.RequestOpts{
			OkCodes: []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		})
		if err != nil {
			return fmt.Errorf("deleting bay %s: %w", bay.Name, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return nil

	default:
		return fmt.Errorf("magnum/bay: action %q not implemented", rule.Action)
	}
}
