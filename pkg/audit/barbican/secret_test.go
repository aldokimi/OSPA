package barbican

import (
	"context"
	"strings"
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

func TestSecretAuditor_Check_StaleSecretMaterial(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{
		SecretRef:  "https://kms/v1/secrets/abc-123",
		Name:       "old-passphrase",
		SecretType: "passphrase",
		Created:    time.Now().Add(-48 * time.Hour),
		Updated:    time.Now().Add(-48 * time.Hour),
	}

	rule := &policy.Rule{
		Name: "stale-passphrases",
		Check: policy.CheckConditions{
			AgeGT:      "1d",
			SecretType: "passphrase",
		},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for stale passphrase")
	}
	if !strings.Contains(result.Observation, "stale_secret_material") {
		t.Fatalf("expected stale_secret_material observation, got %q", result.Observation)
	}
}

func TestSecretAuditor_Check_SecretTypeFilterMiss(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{
		SecretRef:  "https://kms/v1/secrets/abc-123",
		Name:       "cert",
		SecretType: "certificate",
		Created:    time.Now().Add(-48 * time.Hour),
		Updated:    time.Now().Add(-48 * time.Hour),
	}

	rule := &policy.Rule{
		Name: "stale-passphrases",
		Check: policy.CheckConditions{
			AgeGT:      "1d",
			SecretType: "passphrase",
		},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Fatalf("expected compliant when secret_type does not match, got %q", result.Observation)
	}
}

func TestSecretAuditor_Check_SecretTypeAlone(t *testing.T) {
	auditor := &SecretAuditor{}
	s := secrets.Secret{
		SecretRef:  "https://kms/v1/secrets/abc-123",
		Name:       "key",
		SecretType: "private",
	}

	rule := &policy.Rule{
		Name:  "private-keys",
		Check: policy.CheckConditions{SecretType: "private"},
	}

	result, err := auditor.Check(context.Background(), s, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for matching secret_type")
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
