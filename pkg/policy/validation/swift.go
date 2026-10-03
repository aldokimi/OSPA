package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// SwiftValidator validates Swift service policies.
type SwiftValidator struct{}

func init() {
	policy.RegisterValidator(&SwiftValidator{})
}

func (v *SwiftValidator) ServiceName() string {
	return "swift"
}

func (v *SwiftValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "account":
		if err := validateAllowedChecks(check, []string{"quota_set"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "container":
		if err := validateAllowedChecks(check, []string{"unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "object":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for swift service", ruleName, resourceType)
	}

	return nil
}
