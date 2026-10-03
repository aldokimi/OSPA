package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// MagnumValidator validates Magnum service policies.
type MagnumValidator struct{}

func init() {
	policy.RegisterValidator(&MagnumValidator{})
}

func (v *MagnumValidator) ServiceName() string {
	return "magnum"
}

func (v *MagnumValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	// Clusters expose status and creation/updated timestamps.
	case "cluster":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// Cluster templates expose only creation/updated timestamps.
	case "cluster_template":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// Bays expose status and creation/updated timestamps.
	case "bay":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	// Bay models expose only creation/updated timestamps.
	case "baymodel":
		if err := validateAllowedChecks(check, []string{"age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for magnum service", ruleName, resourceType)
	}

	return nil
}
