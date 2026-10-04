package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

type TroveValidator struct{}

func init() {
	policy.RegisterValidator(&TroveValidator{})
}

func (v *TroveValidator) ServiceName() string { return "trove" }

func (v *TroveValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {
	case "instance":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "cluster":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "backup":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names", "backup_retention_days"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "datastore":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for trove service", ruleName, resourceType)
	}
	return nil
}
