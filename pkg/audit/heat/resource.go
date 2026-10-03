package heat

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type resourceAdapter struct {
	r discoveryservices.HeatResourceInStack
}

func (a resourceAdapter) GetID() string           { return a.r.StackName + "/" + a.r.Name }
func (a resourceAdapter) GetName() string         { return a.r.Name }
func (a resourceAdapter) GetProjectID() string    { return "" }
func (a resourceAdapter) GetStatus() string       { return a.r.Status }
func (a resourceAdapter) GetCreatedAt() time.Time { return a.r.CreationTime }
func (a resourceAdapter) GetUpdatedAt() time.Time { return a.r.UpdatedTime }

// ResourceAuditor audits heat/resource resources (resources inside a stack).
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log
//
// Note: stack resources are only modified through their parent stack's
// template (replace / remove_from_stack), so there is no direct delete
// remediation and only log is offered.
type ResourceAuditor struct{}

func (a *ResourceAuditor) ResourceType() string {
	return "resource"
}

func (a *ResourceAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ResourceAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	r, ok := resource.(discoveryservices.HeatResourceInStack)
	if !ok {
		return nil, fmt.Errorf("expected discovery services HeatResourceInStack, got %T", resource)
	}

	adapter := resourceAdapter{r: r}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *ResourceAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	switch rule.Action {
	case "log":
		return nil
	default:
		return fmt.Errorf("heat/resource: action %q not implemented (resources are modified through their stack)", rule.Action)
	}
}
