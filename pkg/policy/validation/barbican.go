package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// BarbicanValidator validates Barbican service policies.
type BarbicanValidator struct{}

func init() {
	policy.RegisterValidator(&BarbicanValidator{})
}

func (v *BarbicanValidator) ServiceName() string {
	return "barbican"
}

func (v *BarbicanValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "secret":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "secret_type", "secret_risk"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "container":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "order":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for barbican service", ruleName, resourceType)
	}

	return nil
}
