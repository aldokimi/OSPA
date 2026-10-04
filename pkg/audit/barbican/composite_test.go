package barbican

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
)

func TestCompositeAuditor_HighRiskStaleSecret(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"secret": {{
			Resource: secrets.Secret{
				SecretRef:  "https://kms/v1/secrets/key-1",
				Name:       "old-key",
				SecretType: "private",
				Created:    time.Now().Add(-72 * time.Hour),
				Updated:    time.Now().Add(-72 * time.Hour),
			},
		}},
	}

	rule := &policy.CompositeRule{
		Name: "stale-keys",
		Check: map[string]interface{}{
			"pattern": "high_risk_stale_secret",
			"age_gt":  "1d",
		},
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for stale high-risk secret")
	}
	if !strings.Contains(result.Observation, "high_risk_stale_secret") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}
