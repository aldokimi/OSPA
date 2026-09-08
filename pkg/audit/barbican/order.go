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
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/orders"
)

type orderAdapter struct{ o orders.Order }

func (a orderAdapter) GetID() string           { return discoveryservices.BarbicanRefID(a.o.OrderRef) }
func (a orderAdapter) GetName() string         { return discoveryservices.BarbicanRefID(a.o.OrderRef) } // orders have no display name
func (a orderAdapter) GetProjectID() string    { return "" }                                            // not exposed on the order resource itself
func (a orderAdapter) GetStatus() string       { return a.o.Status }
func (a orderAdapter) GetCreatedAt() time.Time { return a.o.Created }
func (a orderAdapter) GetUpdatedAt() time.Time { return a.o.Updated }

// OrderAuditor audits barbican/order resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: an order has no display name of its own, so exempt_names matches
// against its ID instead. "unused" is not offered: an order is a one-time
// request to generate a secret, not an ongoing resource with a notion of
// use.
type OrderAuditor struct{}

func (a *OrderAuditor) ResourceType() string {
	return "order"
}

func (a *OrderAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *OrderAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	o, ok := resource.(orders.Order)
	if !ok {
		return nil, fmt.Errorf("expected orders.Order, got %T", resource)
	}

	adapter := orderAdapter{o: o}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *OrderAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	o, ok := resource.(orders.Order)
	if !ok {
		return fmt.Errorf("expected orders.Order, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		id := discoveryservices.BarbicanRefID(o.OrderRef)
		if err := orders.Delete(c, id).ExtractErr(); err != nil {
			return fmt.Errorf("deleting order %s: %w", id, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("barbican/order: tag action not yet implemented")

	default:
		return fmt.Errorf("barbican/order: action %q not implemented", rule.Action)
	}
}
