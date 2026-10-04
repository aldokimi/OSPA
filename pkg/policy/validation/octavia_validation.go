package validation

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

// OctaviaValidator validates Octavia service policies.
type OctaviaValidator struct{}

func init() {
	policy.RegisterValidator(&OctaviaValidator{})
}

func (v *OctaviaValidator) ServiceName() string { return "octavia" }

func (v *OctaviaValidator) ValidateResource(check *policy.CheckConditions, resourceType, ruleName string) error {
	switch resourceType {
	case "loadbalancer":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "listener":
		if err := validateAllowedChecks(check, []string{"status", "exempt_names", "protocol", "port", "tls_ciphers", "has_tls_container"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "pool":
		if err := validateAllowedChecks(check, []string{"status", "exempt_names", "protocol"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "member":
		if err := validateAllowedChecks(check, []string{"status", "age_gt", "exempt_names", "port"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	case "healthmonitor":
		if err := validateAllowedChecks(check, []string{"status", "exempt_names"}); err != nil {
			return fmt.Errorf("rule %q: %w", ruleName, err)
		}
	default:
		return fmt.Errorf("rule %q: unsupported resource type %q for octavia service", ruleName, resourceType)
	}
	return nil
}
