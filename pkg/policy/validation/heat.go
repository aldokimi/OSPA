package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// HeatValidator validates Heat service policies.
type HeatValidator struct{}

func init() {
	policy.RegisterValidator(&HeatValidator{})
}

func (v *HeatValidator) ServiceName() string {
	return "heat"
}

func (v *HeatValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	// Stacks expose stack_status and creation/updated timestamps.
	case "stack":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// Stack resources expose resource_status and creation/updated timestamps.
	case "resource":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// A template is a read-only view of its stack definition: no status,
	// no timestamps. Only the owning stack's name is available, so only
	// exempt_names applies.
	case "template":
		if err := validateAllowedChecks(check, []string{"exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// Snapshots only expose snapshot_time; there is no state field.
	case "snapshot":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for heat service", ruleName, resourceType)
	}

	return nil
}
