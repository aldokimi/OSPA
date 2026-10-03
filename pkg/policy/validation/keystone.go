package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// KeystoneValidator validates Keystone service policies.
type KeystoneValidator struct{}

func init() {
	policy.RegisterValidator(&KeystoneValidator{})
}

func (v *KeystoneValidator) ServiceName() string {
	return "keystone"
}

func (v *KeystoneValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {

	case "user":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names", "password_expired", "has_admin_role", "mfa_enabled"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "role":
		// Roles have no status field in keystone v3, so status is not
		// offered (matches RoleAuditor.ImplementedChecks).
		if err := validateAllowedChecks(check, []string{"age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "project":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "domain":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "group":
		// Groups have no status field in keystone v3, so status is not
		// offered (matches GroupAuditor.ImplementedChecks).
		if err := validateAllowedChecks(check, []string{"age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	case "service":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "unused", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}

	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for keystone service", ruleName, resourceType)
	}

	return nil
}
