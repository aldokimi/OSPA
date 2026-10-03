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

type bayModelAdapter struct {
	m discoveryservices.MagnumBayModel
}

func (a bayModelAdapter) GetID() string           { return a.m.ID }
func (a bayModelAdapter) GetName() string         { return a.m.Name }
func (a bayModelAdapter) GetProjectID() string    { return "" }
func (a bayModelAdapter) GetStatus() string       { return "" } // bay models have no state field
func (a bayModelAdapter) GetCreatedAt() time.Time { return a.m.CreatedAt }
func (a bayModelAdapter) GetUpdatedAt() time.Time { return a.m.UpdatedAt }

// BayModelAuditor audits magnum/baymodel resources.
//
// Allowed checks: age_gt, exempt_names
// Allowed actions: log, delete
//
// Note: bay models expose no status field, so status and unused are not
// offered.
type BayModelAuditor struct{}

func (a *BayModelAuditor) ResourceType() string {
	return "baymodel"
}

func (a *BayModelAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *BayModelAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	m, ok := resource.(discoveryservices.MagnumBayModel)
	if !ok {
		return nil, fmt.Errorf("expected discovery services MagnumBayModel, got %T", resource)
	}

	adapter := bayModelAdapter{m: m}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *BayModelAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	model, ok := resource.(discoveryservices.MagnumBayModel)
	if !ok {
		return fmt.Errorf("expected discovery services MagnumBayModel, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		resp, err := c.Request("DELETE", c.ServiceURL("baymodels", model.ID), &gophercloud.RequestOpts{
			OkCodes: []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		})
		if err != nil {
			return fmt.Errorf("deleting bay model %s: %w", model.Name, err)
		}
		defer resp.Body.Close()
		return nil

	default:
		return fmt.Errorf("magnum/baymodel: action %q not implemented", rule.Action)
	}
}
