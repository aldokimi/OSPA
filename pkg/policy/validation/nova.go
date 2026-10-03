package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// NovaValidator validates Nova service policies.
type NovaValidator struct{}

func init() {
	policy.RegisterValidator(&NovaValidator{})
}

func (v *NovaValidator) ServiceName() string {
	return "nova"
}

func (v *NovaValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "instance":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "image_name", "no_keypair"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "keypair":
		if err := validateAllowedChecks(check, []string{"age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "flavor":
		if err := validateAllowedChecks(check, []string{"exempt_names", "is_public"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "hypervisor":
		if err := validateAllowedChecks(check, []string{"status", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for nova service", ruleName, resourceType)
	}

	return nil
}
