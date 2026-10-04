package keystone

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

func TestCompositeAuditor_ServiceAccountNoMFA(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"user": {{
			Resource: users.User{
				ID:    "u-1",
				Name:  "nova",
				Extra: map[string]interface{}{"type": "service"},
				Options: map[string]interface{}{
					"multi_factor_auth_enabled": "false",
				},
			},
		}},
	}

	rule := &policy.CompositeRule{
		Name:  "service-mfa",
		Check: map[string]interface{}{"pattern": "service_account_no_mfa"},
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for service account without MFA")
	}
	if !strings.Contains(result.Observation, "service_account_no_mfa") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}
