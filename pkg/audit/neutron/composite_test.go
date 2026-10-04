package neutron

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
)

func TestCompositeAuditor_Registered(t *testing.T) {
	a, ok := audit.GetComposite("neutron")
	if !ok {
		t.Fatal("expected neutron CompositeAuditor to be registered")
	}
	if a.Service() != "neutron" {
		t.Fatalf("Service() = %q", a.Service())
	}
}

func TestCompositeAuditor_SharedNetworkWorldExposure(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"network": {{
			ResourceType: "network",
			Resource:     networks.Network{ID: "net-1", Name: "shared-net", Shared: true, TenantID: "t1"},
		}},
		"port": {{
			ResourceType: "port",
			Resource:     ports.Port{ID: "port-1", NetworkID: "net-1", SecurityGroups: []string{"sg-1"}},
		}},
		"security_group_rule": {{
			ResourceType: "security_group_rule",
			Resource: rules.SecGroupRule{
				ID:             "rule-1",
				SecGroupID:     "sg-1",
				RemoteIPPrefix: "0.0.0.0/0",
				Direction:      "ingress",
				Protocol:       "tcp",
				PortRangeMin:   22,
				PortRangeMax:   22,
			},
		}},
	}

	rule := &policy.CompositeRule{
		Name:      "shared-world",
		Service:   "neutron",
		Resources: []string{"network", "port", "security_group_rule"},
		Check:     map[string]interface{}{"pattern": "shared_network_world_exposure"},
		Action:    "log",
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for shared network with world-open SG")
	}
	if !strings.Contains(result.Observation, "shared_network_world_exposure") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}

func TestCompositeAuditor_SharedNetworkWorldExposure_NoHit(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"network": {{
			Resource: networks.Network{ID: "net-1", Name: "private", Shared: false},
		}},
		"port": {{
			Resource: ports.Port{ID: "port-1", NetworkID: "net-1", SecurityGroups: []string{"sg-1"}},
		}},
		"security_group_rule": {{
			Resource: rules.SecGroupRule{ID: "rule-1", SecGroupID: "sg-1", RemoteIPPrefix: "0.0.0.0/0"},
		}},
	}

	rule := &policy.CompositeRule{
		Name:  "shared-world",
		Check: map[string]interface{}{"shared_network_world_exposure": true},
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Fatalf("expected compliant, got %q", result.Observation)
	}
}
