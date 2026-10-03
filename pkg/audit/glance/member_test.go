package glance

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

func TestMemberAuditor_ResourceType(t *testing.T) {
	auditor := &MemberAuditor{}
	if got := auditor.ResourceType(); got != "member" {
		t.Errorf("ResourceType() = %q, want %q", got, "member")
	}
}

func TestMemberAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456", Status: "pending"}

	rule := &policy.Rule{
		Name:  "find-pending-members",
		Check: policy.CheckConditions{Status: "pending"},
	}

	result, err := auditor.Check(context.Background(), m, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for pending member")
	}
	if result.ResourceID != "img-123/proj-456" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "img-123/proj-456")
	}
}

func TestMemberAuditor_Check_Unused(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456", Status: "pending"}

	rule := &policy.Rule{
		Name:  "find-pending-shares",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), m, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for pending share")
	}
}

func TestMemberAuditor_Check_ExemptName(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456", Status: "pending"}

	rule := &policy.Rule{
		Name:  "find-pending-members",
		Check: policy.CheckConditions{Status: "pending", ExemptNames: []string{"proj-456"}},
	}

	result, err := auditor.Check(context.Background(), m, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt member")
	}
}

func TestMemberAuditor_Check_InvalidType(t *testing.T) {
	auditor := &MemberAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-member", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestMemberAuditor_Fix_Log(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, m, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestMemberAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, m, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestMemberAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &MemberAuditor{}
	m := members.Member{ImageID: "img-123", MemberID: "proj-456"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, m, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
