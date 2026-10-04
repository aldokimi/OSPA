package nova

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

func TestNovaComposite_Registered(t *testing.T) {
	if _, ok := audit.GetComposite("nova"); !ok {
		t.Fatal("expected nova CompositeAuditor")
	}
}

func TestNovaComposite_PublicFlavorNetworkBinding(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"flavor": {{
			Resource: flavors.Flavor{ID: "flv-1", Name: "m1.tiny", IsPublic: true},
		}},
		"instance": {{
			Resource: servers.Server{
				ID:       "srv-1",
				Name:     "web",
				TenantID: "t1",
				Flavor:   map[string]interface{}{"id": "flv-1"},
				Addresses: map[string]interface{}{
					"public": []interface{}{},
				},
			},
		}},
	}
	rule := &policy.CompositeRule{
		Name:      "public-flavor-bound",
		Resources: []string{"flavor", "instance"},
		Check:     map[string]interface{}{"pattern": "public_flavor_network_binding"},
	}
	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant || !strings.Contains(result.Observation, "public_flavor_network_binding") {
		t.Fatalf("unexpected: compliant=%v obs=%q", result.Compliant, result.Observation)
	}
}
