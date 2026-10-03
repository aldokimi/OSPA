package nova

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
)

func TestKeypairAuditor_ResourceType(t *testing.T) {
	auditor := &KeypairAuditor{}
	if got := auditor.ResourceType(); got != "keypair" {
		t.Errorf("ResourceType() = %q, want %q", got, "keypair")
	}
}

func TestKeypairAuditor_Check_ExemptName(t *testing.T) {
	auditor := &KeypairAuditor{}
	k := keypairs.KeyPair{Name: "default"}

	rule := &policy.Rule{
		Name:  "find-old-keypairs",
		Check: policy.CheckConditions{AgeGT: "30d", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), k, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt keypair")
	}
}

func TestKeypairAuditor_Check_AgeGT_NoOp(t *testing.T) {
	auditor := &KeypairAuditor{}
	k := keypairs.KeyPair{Name: "old-keypair"}

	rule := &policy.Rule{
		Name:  "find-old-keypairs",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}

	result, err := auditor.Check(context.Background(), k, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant (age_gt is a no-op without timestamps)")
	}
	if result.ResourceID != "old-keypair" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "old-keypair")
	}
}

func TestKeypairAuditor_Check_InvalidType(t *testing.T) {
	auditor := &KeypairAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-keypair", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestKeypairAuditor_Fix_Log(t *testing.T) {
	auditor := &KeypairAuditor{}
	k := keypairs.KeyPair{Name: "kp-1"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, k, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestKeypairAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &KeypairAuditor{}
	k := keypairs.KeyPair{Name: "kp-1"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, k, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestKeypairAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &KeypairAuditor{}
	k := keypairs.KeyPair{Name: "kp-1"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, k, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
