package neutron

import (
	"context"
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
)

func TestSecurityGroupRuleAuditor_ResourceType(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}
	if got := auditor.ResourceType(); got != "security_group_rule" {
		t.Errorf("ResourceType() = %q, want %q", got, "security_group_rule")
	}
}

func TestSecurityGroupRuleAuditor_ImplementedChecks_IncludesPortRangeWide(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}
	got := auditor.ImplementedChecks()
	found := false
	for _, c := range got {
		if c == "port_range_wide" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ImplementedChecks() missing port_range_wide: %v", got)
	}
}

func TestSecurityGroupRuleAuditor_Check_SSHOpenToWorld(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	rule := &policy.Rule{
		Name:     "test-ssh-open-to-world",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Direction:      "ingress",
			Ethertype:      "IPv4",
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Expected SSH open to world rule to be non-compliant")
	}
	if !strings.Contains(result.Observation, "public_sensitive_service_exposure") {
		t.Errorf("Expected semantic exposure observation, got %q", result.Observation)
	}
}

func TestSecurityGroupRuleAuditor_Check_SSHOpenToWorld_Egress(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "egress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	rule := &policy.Rule{
		Name:     "test-ssh-open-to-world-egress",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Direction:      "egress",
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Expected SSH world-open egress rule to be non-compliant")
	}
	if !strings.Contains(result.Observation, "public_sensitive_service_exposure") {
		t.Errorf("Expected semantic exposure observation, got %q", result.Observation)
	}
}

func TestSecurityGroupRuleAuditor_Check_SSHOpenToWorld_BothDirections_Escalation(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	rule := &policy.Rule{
		Name:     "test-ssh-open-to-world-both",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Expected SSH world-open both-directions escalation to be non-compliant")
	}
	if !strings.Contains(result.Observation, "bidirectional_world_exposure") {
		t.Errorf("Expected bidirectional escalation observation, got %q", result.Observation)
	}
}

func TestSecurityGroupRuleAuditor_Check_SafeRule(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "10.0.0.0/8",
	}

	rule := &policy.Rule{
		Name:     "test-ssh-open-to-world",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Direction:      "ingress",
			Ethertype:      "IPv4",
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Expected safe SSH rule (private network) to be compliant")
	}
}

func TestSecurityGroupRuleAuditor_Check_PortRange(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "tcp",
		PortRangeMin:   20,
		PortRangeMax:   25,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	rule := &policy.Rule{
		Name:     "test-ssh-port-range",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Direction:      "ingress",
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Expected rule with port range including 22 to be non-compliant")
	}
}

func TestSecurityGroupRuleAuditor_Check_PartialMatch(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	resource := rules.SecGroupRule{
		ID:             "test-rule-id",
		SecGroupID:     "test-sg-id",
		TenantID:       "test-tenant-id",
		Direction:      "ingress",
		EtherType:      "IPv4",
		Protocol:       "udp",
		PortRangeMin:   22,
		PortRangeMax:   22,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	rule := &policy.Rule{
		Name:     "test-ssh-tcp-only",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check: policy.CheckConditions{
			Direction:      "ingress",
			Protocol:       "tcp",
			Port:           22,
			RemoteIPPrefix: "0.0.0.0/0",
		},
		Action: "log",
	}

	result, err := auditor.Check(context.Background(), resource, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Expected UDP rule to be compliant when looking for TCP")
	}
}

func TestSecurityGroupRuleAuditor_Check_PortRangeWide(t *testing.T) {
	auditor := &SecurityGroupRuleAuditor{}

	wide := rules.SecGroupRule{
		ID:           "wide",
		SecGroupID:   "sg",
		TenantID:     "t",
		Direction:    "ingress",
		EtherType:    "IPv4",
		Protocol:     "tcp",
		PortRangeMin: 1,
		PortRangeMax: 1024, // span 1023 > 100
	}
	narrow := rules.SecGroupRule{
		ID:           "narrow",
		SecGroupID:   "sg",
		TenantID:     "t",
		Direction:    "ingress",
		EtherType:    "IPv4",
		Protocol:     "tcp",
		PortRangeMin: 80,
		PortRangeMax: 90,
	}

	rule := &policy.Rule{
		Name:     "wide-ranges",
		Service:  "neutron",
		Resource: "security_group_rule",
		Check:    policy.CheckConditions{PortRangeWide: true},
		Action:   "log",
	}

	wideResult, err := auditor.Check(context.Background(), wide, rule)
	if err != nil {
		t.Fatalf("wide Check() error = %v", err)
	}
	if wideResult.Compliant {
		t.Error("Expected wide port range to be non-compliant")
	}

	narrowResult, err := auditor.Check(context.Background(), narrow, rule)
	if err != nil {
		t.Fatalf("narrow Check() error = %v", err)
	}
	if !narrowResult.Compliant {
		t.Error("Expected narrow port range to be compliant")
	}
}

func TestSecurityGroupRuleAuditor_Fix(t *testing.T) {
	t.Skip("Fix() requires a mock gophercloud client")
}

func TestBuildRuleName(t *testing.T) {
	tests := []struct {
		name     string
		rule     rules.SecGroupRule
		expected string
	}{
		{
			name: "SSH ingress from anywhere",
			rule: rules.SecGroupRule{
				Direction:      "ingress",
				Protocol:       "tcp",
				PortRangeMin:   22,
				PortRangeMax:   22,
				RemoteIPPrefix: "0.0.0.0/0",
			},
			expected: "ingress/tcp:22 from 0.0.0.0/0",
		},
		{
			name: "Port range",
			rule: rules.SecGroupRule{
				Direction:      "ingress",
				Protocol:       "tcp",
				PortRangeMin:   80,
				PortRangeMax:   443,
				RemoteIPPrefix: "10.0.0.0/8",
			},
			expected: "ingress/tcp:80-443 from 10.0.0.0/8",
		},
		{
			name: "All traffic",
			rule: rules.SecGroupRule{
				Direction:      "egress",
				Protocol:       "",
				PortRangeMin:   0,
				PortRangeMax:   0,
				RemoteIPPrefix: "",
			},
			expected: "egress/any from any",
		},
		{
			name: "Remote security group",
			rule: rules.SecGroupRule{
				Direction:     "ingress",
				Protocol:      "tcp",
				PortRangeMin:  22,
				PortRangeMax:  22,
				RemoteGroupID: "sg-12345",
			},
			expected: "ingress/tcp:22 from sg:sg-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRuleName(tt.rule)
			if got != tt.expected {
				t.Errorf("buildRuleName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPortMatches(t *testing.T) {
	tests := []struct {
		name     string
		min      int
		max      int
		port     int
		expected bool
	}{
		{"exact match", 22, 22, 22, true},
		{"in range", 20, 25, 22, true},
		{"below range", 20, 25, 19, false},
		{"above range", 20, 25, 26, false},
		{"all ports (0-0)", 0, 0, 22, true},
		{"all ports matches any", 0, 0, 443, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portMatches(tt.min, tt.max, tt.port)
			if got != tt.expected {
				t.Errorf("portMatches(%d, %d, %d) = %v, want %v", tt.min, tt.max, tt.port, got, tt.expected)
			}
		})
	}
}

func TestIsPortRangeWide(t *testing.T) {
	if !isPortRangeWide(1, 1024) {
		t.Error("expected 1-1024 to be wide")
	}
	if isPortRangeWide(80, 90) {
		t.Error("expected 80-90 not to be wide")
	}
	if !isPortRangeWide(0, 0) {
		t.Error("expected all-ports (0-0) to be wide")
	}
}
