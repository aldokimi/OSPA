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

type templateAdapter struct {
	t discoveryservices.HeatTemplate
}

func (a templateAdapter) GetID() string           { return a.t.StackID }
func (a templateAdapter) GetName() string         { return a.t.StackName }
func (a templateAdapter) GetProjectID() string    { return "" }
func (a templateAdapter) GetStatus() string       { return "" } // templates have no status
func (a templateAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a templateAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// TemplateAuditor audits heat/template resources (a stack's template).
//
// Allowed checks: exempt_names
// Allowed actions: log
//
// Note: a stack template is a read-only view of the stack definition (the
// API only supports GET and validate); it carries no status or timestamps,
// so only exempt_names - matching on the owning stack's name - applies.
type TemplateAuditor struct{}

func (a *TemplateAuditor) ResourceType() string {
	return "template"
}

func (a *TemplateAuditor) ImplementedChecks() []string {
	return []string{"exempt_names"}
}

func (a *TemplateAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	t, ok := resource.(discoveryservices.HeatTemplate)
	if !ok {
		return nil, fmt.Errorf("expected discovery services HeatTemplate, got %T", resource)
	}

	adapter := templateAdapter{t: t}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	return result, nil
}

func (a *TemplateAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource

	switch rule.Action {
	case "log":
		return nil
	default:
		return fmt.Errorf("heat/template: action %q not implemented (templates are modified through their stack)", rule.Action)
	}
}
