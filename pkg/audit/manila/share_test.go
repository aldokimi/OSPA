package manila

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func TestShareAuditor_Check_IsPublic(t *testing.T) {
	auditor := &ShareAuditor{}
	wantPublic := false
	share := discoveryservices.ManilaShare{
		ID:       "sh-1",
		Name:     "public-share",
		Status:   "available",
		IsPublic: true,
	}

	rule := &policy.Rule{
		Name:  "no-public-shares",
		Check: policy.CheckConditions{IsPublic: &wantPublic},
	}

	result, err := auditor.Check(context.Background(), share, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for public share")
	}
}

func TestShareAuditor_Check_Status(t *testing.T) {
	auditor := &ShareAuditor{}
	share := discoveryservices.ManilaShare{ID: "sh-2", Name: "broken", Status: "error"}

	rule := &policy.Rule{
		Name:  "find-error-shares",
		Check: policy.CheckConditions{Status: "error"},
	}

	result, err := auditor.Check(context.Background(), share, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for error status")
	}
}
