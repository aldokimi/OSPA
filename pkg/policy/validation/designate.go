package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// DesignateValidator validates Designate service policies.
type DesignateValidator struct{}

func init() {
	policy.RegisterValidator(&DesignateValidator{})
}

func (v *DesignateValidator) ServiceName() string {
	return "designate"
}

func (v *DesignateValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "zone":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "recordset":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "record_type"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "record":
		// Records are single values within a recordset (there is no
		// standalone Designate record API), so an unused check is not
		// offered (matches RecordAuditor.ImplementedChecks).
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for designate service", ruleName, resourceType)
	}

	return nil
}
