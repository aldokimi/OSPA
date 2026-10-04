package keystone

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
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
// Note: keystone's v3 User has no creation timestamp in the base API, so
// age_gt is accepted for policy consistency but is a no-op. inactive_days
// is not offered at all: there is no last-login field in the base identity
// API to evaluate it against. has_admin_role requires enumerating the
// user's role assignments, which Check() cannot do without a client, so it
// is left as a pending observation. password_expired and mfa_enabled are
// backed by real fields (PasswordExpiresAt, and the
// "multi_factor_auth_enabled" user option) and are fully implemented.
type UserAuditor struct{}

func (a *UserAuditor) ResourceType() string {
	return "user"
}

func (a *UserAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "password_expired", "has_admin_role", "mfa_enabled"}
}

func (a *UserAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

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

	// #111 catalog outcome when both atomics fire together.
	if passwordExpiredHit && mfaHit {
		result.Observation = fmt.Sprintf(
			"expired_password_no_mfa: password expired at %s and MFA enabled is %t",
			u.PasswordExpiresAt.Format(time.RFC3339), mfaEnabled,
		)
	}

	if rule.Check.HasAdminRole {
		result.Observation = "has_admin_role check pending - requires role assignment enumeration"
	}

	return result, nil
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
