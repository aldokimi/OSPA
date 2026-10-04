package keystone

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

// parseBoolOption interprets a Keystone user option value. The v3 API
// serializes option values as JSON strings (e.g. "true"/"false"), so a plain
// type assertion to bool always fails; accept both the string and a native
// bool (for tests and any future API change).
func parseBoolOption(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(t)
		if err != nil {
			return false
		}
		return b
	default:
		return false
	}
}

type userAdapter struct{ u users.User }

func (a userAdapter) GetID() string        { return a.u.ID }
func (a userAdapter) GetName() string      { return a.u.Name }
func (a userAdapter) GetProjectID() string { return a.u.DefaultProjectID }

// GetStatus derives a status string from Enabled, since keystone's v3 User
// has no status field of its own.
func (a userAdapter) GetStatus() string {
	if a.u.Enabled {
		return "enabled"
	}
	return "disabled"
}
func (a userAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a userAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// UserAuditor audits keystone/user resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, password_expired,
// has_admin_role, mfa_enabled
// Allowed actions: log, delete, tag
//
// has_admin_role enumerates role assignments via the service client passed in
// context (audit.WithClient). Roles named "admin" (case-insensitive) count as
// high privilege. Combined with mfa_enabled, emits high_privilege_no_mfa.
type UserAuditor struct{}

func (a *UserAuditor) ResourceType() string {
	return "user"
}

func (a *UserAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "password_expired", "has_admin_role", "mfa_enabled"}
}

func (a *UserAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	u, ok := resource.(users.User)
	if !ok {
		return nil, fmt.Errorf("expected users.User, got %T", resource)
	}

	adapter := userAdapter{u: u}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && !u.Enabled {
		result.Compliant = false
		result.Observation = "user account is disabled"
	}

	passwordExpiredHit := false
	if rule.Check.PasswordExpired {
		if !u.PasswordExpiresAt.IsZero() && time.Now().After(u.PasswordExpiresAt) {
			passwordExpiredHit = true
			result.Compliant = false
			result.Observation = fmt.Sprintf("password expired at %s", u.PasswordExpiresAt.Format(time.RFC3339))
		}
	}

	mfaHit := false
	mfaEnabled := parseBoolOption(u.Options["multi_factor_auth_enabled"])
	if rule.Check.MFAEnabled != nil {
		if mfaEnabled != *rule.Check.MFAEnabled {
			mfaHit = true
			result.Compliant = false
			result.Observation = fmt.Sprintf("user MFA enabled is %t", mfaEnabled)
		}
	}

	if passwordExpiredHit && mfaHit {
		result.Observation = fmt.Sprintf(
			"expired_password_no_mfa: password expired at %s and MFA enabled is %t",
			u.PasswordExpiresAt.Format(time.RFC3339), mfaEnabled,
		)
	}

	adminHit := false
	if rule.Check.HasAdminRole {
		hasAdmin, adminErr := userHasAdminRole(ctx, u.ID)
		if adminErr != nil {
			result.Observation = fmt.Sprintf("has_admin_role check failed: %v", adminErr)
			return result, nil
		}
		if hasAdmin {
			adminHit = true
			result.Compliant = false
			result.Observation = "user has admin role assigned"
		}
	}

	// #105 catalog outcome: admin + MFA posture violation.
	if adminHit && mfaHit {
		result.Observation = fmt.Sprintf(
			"high_privilege_no_mfa: user has admin role and MFA enabled is %t",
			mfaEnabled,
		)
	}

	return result, nil
}

func userHasAdminRole(ctx context.Context, userID string) (bool, error) {
	raw, ok := audit.ClientFromContext(ctx)
	if !ok {
		return false, fmt.Errorf("service client not available in context")
	}
	c, ok := raw.(*gophercloud.ServiceClient)
	if !ok {
		return false, fmt.Errorf("expected *gophercloud.ServiceClient, got %T", raw)
	}

	effective := true
	includeNames := true
	pages, err := roles.ListAssignments(c, roles.ListAssignmentsOpts{
		UserID:       userID,
		Effective:    &effective,
		IncludeNames: &includeNames,
	}).AllPages()
	if err != nil {
		return false, err
	}
	assignments, err := roles.ExtractRoleAssignments(pages)
	if err != nil {
		return false, err
	}
	for _, as := range assignments {
		if strings.EqualFold(as.Role.Name, "admin") {
			return true, nil
		}
	}
	return false, nil
}

func (a *UserAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	u, ok := resource.(users.User)
	if !ok {
		return fmt.Errorf("expected users.User, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := users.Delete(c, u.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting user %s: %w", u.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("keystone/user: tag action not yet implemented")

	default:
		return fmt.Errorf("keystone/user: action %q not implemented", rule.Action)
	}
}
