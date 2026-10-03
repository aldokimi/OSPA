package cinder

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/qos"
)

type qosAdapter struct{ q qos.QoS }

func (a qosAdapter) GetID() string           { return a.q.ID }
func (a qosAdapter) GetName() string         { return a.q.Name }
func (a qosAdapter) GetProjectID() string    { return "" } // QoS specs are global, not project-scoped
func (a qosAdapter) GetStatus() string       { return "" } // QoS specs have no status
func (a qosAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a qosAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// QosAuditor audits cinder/qos resources.
//
// Allowed checks: exempt_names
// Allowed actions: log, delete, tag
//
// Note: QoS specifications are global, admin-only objects with no status,
// project scoping, or timestamps, so only exempt_names is meaningful.
type QosAuditor struct{}

func (a *QosAuditor) ResourceType() string {
	return "qos"
}

func (a *QosAuditor) ImplementedChecks() []string {
	return []string{"exempt_names"}
}

func (a *QosAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	q, ok := resource.(qos.QoS)
	if !ok {
		return nil, fmt.Errorf("expected qos.QoS, got %T", resource)
	}

	adapter := qosAdapter{q: q}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	return result, nil
}

func (a *QosAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	q, ok := resource.(qos.QoS)
	if !ok {
		return fmt.Errorf("expected qos.QoS, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := qos.Delete(c, q.ID, qos.DeleteOpts{}).ExtractErr(); err != nil {
			return fmt.Errorf("deleting qos spec %s: %w", q.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("cinder/qos: tag action not yet implemented")

	default:
		return fmt.Errorf("cinder/qos: action %q not implemented", rule.Action)
	}
}
