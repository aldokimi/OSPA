package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// GlanceValidator validates Glance service policies.
type GlanceValidator struct{}

func init() {
	policy.RegisterValidator(&GlanceValidator{})
}

func (v *GlanceValidator) ServiceName() string {
	return "glance"
}

func (v *GlanceValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "image":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "visibility"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "member":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for glance service", ruleName, resourceType)
	}

	return nil
}
