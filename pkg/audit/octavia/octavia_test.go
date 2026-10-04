package octavia

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
)

func TestListenerAuditor_InsecureHTTP(t *testing.T) {
	auditor := &ListenerAuditor{}
	l := listeners.Listener{
		ID:           "l1",
		Name:         "web",
		Protocol:     "HTTP",
		ProtocolPort: 80,
	}
	rule := &policy.Rule{
		Name:  "no-http",
		Check: policy.CheckConditions{Protocol: "HTTP"},
	}
	result, err := auditor.Check(context.Background(), l, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for HTTP listener")
	}
	if !strings.Contains(result.Observation, "insecure_listener_tls") {
		t.Fatalf("observation = %q, want insecure_listener_tls", result.Observation)
	}
}

func TestListenerAuditor_MissingTLSContainer(t *testing.T) {
	auditor := &ListenerAuditor{}
	falseVal := false
	l := listeners.Listener{
		ID:                     "l2",
		Name:                   "tls",
		Protocol:               "TERMINATED_HTTPS",
		ProtocolPort:           443,
		DefaultTlsContainerRef: "",
	}
	rule := &policy.Rule{
		Name: "require-tls-secret",
		Check: policy.CheckConditions{
			Protocol:        "TERMINATED_HTTPS",
			Port:            443,
			HasTlsContainer: &falseVal,
		},
	}
	result, err := auditor.Check(context.Background(), l, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant when TERMINATED_HTTPS has no tls container")
	}
	if !strings.Contains(result.Observation, "insecure_listener_tls") {
		t.Fatalf("observation = %q, want insecure_listener_tls", result.Observation)
	}
}

func TestListenerAuditor_TlsCiphersMatch(t *testing.T) {
	auditor := &ListenerAuditor{}
	l := listeners.Listener{
		ID:           "l3",
		Name:         "weak",
		Protocol:     "TERMINATED_HTTPS",
		ProtocolPort: 443,
		TLSCiphers:   "RC4-SHA",
	}
	rule := &policy.Rule{
		Name:  "find-weak-ciphers",
		Check: policy.CheckConditions{TlsCiphers: "RC4-SHA"},
	}
	result, err := auditor.Check(context.Background(), l, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for matching weak tls_ciphers")
	}
}

func TestListenerAuditor_NoMatch(t *testing.T) {
	auditor := &ListenerAuditor{}
	l := listeners.Listener{
		ID:                     "l4",
		Name:                   "secure",
		Protocol:               "TERMINATED_HTTPS",
		ProtocolPort:           443,
		DefaultTlsContainerRef: "secret://abc",
		TLSCiphers:             "ECDHE-RSA-AES256-GCM-SHA384",
	}
	falseVal := false
	rule := &policy.Rule{
		Name: "require-tls-secret",
		Check: policy.CheckConditions{
			Protocol:        "TERMINATED_HTTPS",
			HasTlsContainer: &falseVal,
		},
	}
	result, err := auditor.Check(context.Background(), l, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Fatalf("expected compliant when has_tls_container mismatch, got %q", result.Observation)
	}
}

func TestLoadBalancerAuditor_AgeGT(t *testing.T) {
	auditor := &LoadBalancerAuditor{}
	old := time.Now().Add(-60 * 24 * time.Hour)
	lb := loadbalancers.LoadBalancer{
		ID:                 "lb1",
		Name:               "old-lb",
		ProvisioningStatus: "ACTIVE",
		CreatedAt:          old,
		UpdatedAt:          old,
	}
	rule := &policy.Rule{
		Name:  "old-lbs",
		Check: policy.CheckConditions{AgeGT: "30d"},
	}
	result, err := auditor.Check(context.Background(), lb, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for aged loadbalancer")
	}
}
