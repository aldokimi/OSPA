package barbican

import (
	"context"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
)

func TestSecretAuditor_ResourceType(t *testing.T) {
	auditor := &SecretAuditor{}
	if got := auditor.ResourceType(); got != "secret" {
		t.Errorf("ResourceType() = %q, want %q", got, "secret")
	}
}

func TestSecretAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123", Name: "db-password", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-secrets",
		Check: policy.CheckConditions{Status: "ERROR"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for ERROR secret")
	}
	if result.ResourceID != "abc-123" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "abc-123")
	}
}

func TestSecretAuditor_Check_Expired(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123", Name: "db-password", Expiration: time.Now().Add(-24 * time.Hour)}

	rule := &policy.Rule{
		Name:  "find-expired-secrets",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for expired secret")
	}
}

func TestSecretAuditor_Check_ExemptName(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123", Name: "default", Status: "ERROR"}

	rule := &policy.Rule{
		Name:  "find-error-secrets",
		Check: policy.CheckConditions{Status: "ERROR", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt secret")
	}
}

func TestSecretAuditor_Check_InvalidType(t *testing.T) {
	auditor := &SecretAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-secret", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestSecretAuditor_Fix_Log(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestSecretAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestSecretAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{SecretRef: "https://kms/v1/secrets/abc-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, s, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
