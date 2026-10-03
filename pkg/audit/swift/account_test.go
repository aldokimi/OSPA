package swift

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/accounts"
)

func TestAccountAuditor_ResourceType(t *testing.T) {
	auditor := &AccountAuditor{}
	if got := auditor.ResourceType(); got != "account" {
		t.Errorf("ResourceType() = %q, want %q", got, "account")
	}
}

func TestAccountAuditor_Check_QuotaNotSet(t *testing.T) {
	auditor := &AccountAuditor{}
	h := accounts.GetHeader{QuotaBytes: nil}

	want := true
	rule := &policy.Rule{
		Name:  "require-quota",
		Check: policy.CheckConditions{QuotaSet: &want},
	}

	result, err := auditor.Check(context.Background(), h, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for account with no quota set")
	}
}

func TestAccountAuditor_Check_QuotaSet(t *testing.T) {
	auditor := &AccountAuditor{}
	quota := int64(1000000)
	h := accounts.GetHeader{QuotaBytes: &quota}

	want := true
	rule := &policy.Rule{
		Name:  "require-quota",
		Check: policy.CheckConditions{QuotaSet: &want},
	}

	result, err := auditor.Check(context.Background(), h, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for account with quota set")
	}
}

func TestAccountAuditor_Check_InvalidType(t *testing.T) {
	auditor := &AccountAuditor{}

	_, err := auditor.Check(context.Background(), "not-an-account", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestAccountAuditor_Fix_Log(t *testing.T) {
	auditor := &AccountAuditor{}
	h := accounts.GetHeader{}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, h, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestAccountAuditor_Fix_DeleteNotSupported(t *testing.T) {
	auditor := &AccountAuditor{}
	h := accounts.GetHeader{}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, h, rule); err == nil {
		t.Error("Fix(delete) expected error: accounts have no delete API")
	}
}
