package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type ManillaValidator struct{}

func init() {
	policy.RegisterValidator(&ManillaValidator{})
}

func (v *ManillaValidator) ServiceName() string { return "manila" }

func (v *ManillaValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {
	case "share":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "is_public"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "share_snapshot":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "share_network":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "share_server":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for manila service", ruleName, resourceType)
	}
	return nil
}
