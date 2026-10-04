package heat

import (
	"fmt"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacks"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Heat cross-resource composite patterns.
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "heat" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := heatCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "failed_stack_root_cause":
		return a.checkFailedStackRootCause(resources, result)
	case "":
		return nil, fmt.Errorf("heat composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("heat composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("heat composite: action %q not implemented", rule.Action)
}

func heatCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["failed_stack_root_cause"].(bool); ok && v {
		return "failed_stack_root_cause"
	}
	return ""
}

func isFailedStatus(status string) bool {
	s := strings.ToUpper(status)
	return strings.Contains(s, "FAILED")
}

func (a *CompositeAuditor) checkFailedStackRootCause(
	resources map[string][]discovery.Job,
	result *audit.Result,
) (*audit.Result, error) {
	type failInfo struct {
		name   string
		status string
		reason string
	}

	failedByStack := map[string][]failInfo{}
	for _, job := range resources["resource"] {
		r, ok := job.Resource.(discoveryservices.HeatResourceInStack)
		if !ok || !isFailedStatus(r.Status) {
			continue
		}
		failedByStack[r.StackName] = append(failedByStack[r.StackName], failInfo{
			name:   r.Name,
			status: r.Status,
			reason: r.StatusReason,
		})
	}

	var hitStack *stacks.ListedStack
	var hitFails []failInfo
	for _, job := range resources["stack"] {
		s, ok := job.Resource.(stacks.ListedStack)
		if !ok || !isFailedStatus(s.Status) {
			continue
		}
		fails := failedByStack[s.Name]
		if len(fails) == 0 {
			// Still report failed stack even without failed children.
			fails = []failInfo{}
		}
		hitStack = &s
		hitFails = fails
		break
	}

	if hitStack == nil {
		result.Observation = "failed_stack_root_cause: no failed stacks found"
		return result, nil
	}

	result.Compliant = false
	result.ResourceID = hitStack.ID
	result.ResourceName = hitStack.Name
	if len(hitFails) == 0 {
		result.Observation = fmt.Sprintf(
			"failed_stack_root_cause: stack %q status=%s reason=%q (no failed sub-resources discovered)",
			hitStack.Name, hitStack.Status, hitStack.StatusReason,
		)
		return result, nil
	}

	parts := make([]string, 0, len(hitFails))
	for _, f := range hitFails {
		parts = append(parts, fmt.Sprintf("%s[%s]: %s", f.name, f.status, f.reason))
	}
	result.Observation = fmt.Sprintf(
		"failed_stack_root_cause: stack %q status=%s reason=%q; failed resources: %s",
		hitStack.Name, hitStack.Status, hitStack.StatusReason, strings.Join(parts, "; "),
	)
	return result, nil
}
