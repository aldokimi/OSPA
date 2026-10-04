package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// IronicValidator validates Ironic service policies.
type IronicValidator struct{}

func init() {
	policy.RegisterValidator(&IronicValidator{})
}

func (v *IronicValidator) ServiceName() string {
	return "ironic"
}

func (v *IronicValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "node":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "console_enabled", "boot_interface"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "port":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "driver":
		if err := validateAllowedChecks(check, []string{"exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "chassis":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for ironic service", ruleName, resourceType)
	}

	return nil
}
