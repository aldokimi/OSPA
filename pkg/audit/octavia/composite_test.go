package octavia

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
)

func TestCompositeAuditor_Registered(t *testing.T) {
	if _, ok := audit.GetComposite("octavia"); !ok {
		t.Fatal("expected octavia CompositeAuditor")
	}
}

func TestCompositeAuditor_InsecurePublicListener(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"loadbalancer": {{
			Resource: loadbalancers.LoadBalancer{
				ID:         "lb1",
				Name:       "public-lb",
				VipAddress: "203.0.113.10",
			},
		}},
		"listener": {{
			Resource: listeners.Listener{
				ID:            "l1",
				Name:          "http",
				Protocol:      "HTTP",
				ProtocolPort:  80,
				Loadbalancers: []listeners.LoadBalancerID{{ID: "lb1"}},
			},
		}},
	}
	rule := &policy.CompositeRule{
		Name: "insecure-public",
		Check: map[string]interface{}{
			"pattern": "insecure_public_listener",
		},
	}
	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for world-open HTTP listener")
	}
	if !strings.Contains(result.Observation, "insecure_public_listener") {
		t.Fatalf("observation = %q", result.Observation)
	}
}

func TestCompositeAuditor_InsecurePublicListener_NoHit(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"loadbalancer": {{
			Resource: loadbalancers.LoadBalancer{ID: "lb1", VipAddress: "10.0.0.5"},
		}},
		"listener": {{
			Resource: listeners.Listener{
				ID:                     "l1",
				Protocol:               "TERMINATED_HTTPS",
				ProtocolPort:           443,
				DefaultTlsContainerRef: "secret://ok",
				AllowedCIDRs:           []string{"10.0.0.0/8"},
				Loadbalancers:          []listeners.LoadBalancerID{{ID: "lb1"}},
			},
		}},
	}
	rule := &policy.CompositeRule{
		Name:  "insecure-public",
		Check: map[string]interface{}{"pattern": "insecure_public_listener"},
	}
	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Fatalf("expected compliant, got %q", result.Observation)
	}
}
