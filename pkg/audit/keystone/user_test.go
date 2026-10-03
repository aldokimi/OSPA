package keystone

import (
	"context"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

func TestUserAuditor_ResourceType(t *testing.T) {
	auditor := &UserAuditor{}
	if got := auditor.ResourceType(); got != "user" {
		t.Errorf("ResourceType() = %q, want %q", got, "user")
	}
}

func TestUserAuditor_Check_StatusDisabled(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "jdoe", DefaultProjectID: "proj-456", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-users",
		Check: policy.CheckConditions{Status: "disabled"},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for disabled user")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestUserAuditor_Check_PasswordExpired(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "jdoe", PasswordExpiresAt: time.Now().Add(-24 * time.Hour)}

	rule := &policy.Rule{
		Name:  "find-expired-passwords",
		Check: policy.CheckConditions{PasswordExpired: true},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for expired password")
	}
}

func TestUserAuditor_Check_PasswordNotExpired(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "jdoe", PasswordExpiresAt: time.Now().Add(24 * time.Hour)}

	rule := &policy.Rule{
		Name:  "find-expired-passwords",
		Check: policy.CheckConditions{PasswordExpired: true},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for non-expired password")
	}
}

func TestUserAuditor_Check_MFAEnabled_StringOption(t *testing.T) {
	// Keystone v3 serializes user option values as JSON strings, so the
	// wire value is "true"/"false" (a string), not a Go bool.
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "jdoe", Options: map[string]interface{}{"multi_factor_auth_enabled": "false"}}

	want := true
	rule := &policy.Rule{
		Name:  "require-mfa",
		Check: policy.CheckConditions{MFAEnabled: &want},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for user without MFA when MFA is required")
	}
}

func TestUserAuditor_Check_MFAEnabled_StringOptionSatisfied(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "jdoe", Options: map[string]interface{}{"multi_factor_auth_enabled": "true"}}

	want := true
	rule := &policy.Rule{
		Name:  "require-mfa",
		Check: policy.CheckConditions{MFAEnabled: &want},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for user with MFA when MFA is required")
	}
}

func TestUserAuditor_Check_ExemptName(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123", Name: "admin", Enabled: false}

	rule := &policy.Rule{
		Name:  "find-disabled-users",
		Check: policy.CheckConditions{Status: "disabled", ExemptNames: []string{"admin"}},
	}

	result, err := auditor.Check(context.Background(), u, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt user")
	}
}

func TestUserAuditor_Check_InvalidType(t *testing.T) {
	auditor := &UserAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-user", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestUserAuditor_Fix_Log(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, u, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestUserAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, u, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestUserAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &UserAuditor{}
	u := users.User{ID: "user-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, u, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
