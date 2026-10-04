package octavia

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
)

type loadBalancerAdapter struct{ lb loadbalancers.LoadBalancer }

func (a loadBalancerAdapter) GetID() string           { return a.lb.ID }
func (a loadBalancerAdapter) GetName() string         { return a.lb.Name }
func (a loadBalancerAdapter) GetProjectID() string    { return a.lb.ProjectID }
func (a loadBalancerAdapter) GetStatus() string       { return a.lb.ProvisioningStatus }
func (a loadBalancerAdapter) GetCreatedAt() time.Time { return a.lb.CreatedAt }
func (a loadBalancerAdapter) GetUpdatedAt() time.Time { return a.lb.UpdatedAt }

// LoadBalancerAuditor audits octavia/loadbalancer resources.
type LoadBalancerAuditor struct{}

func (a *LoadBalancerAuditor) ResourceType() string { return "loadbalancer" }
func (a *LoadBalancerAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *LoadBalancerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	lb, ok := resource.(loadbalancers.LoadBalancer)
	if !ok {
		return nil, fmt.Errorf("expected loadbalancers.LoadBalancer, got %T", resource)
	}
	adapter := loadBalancerAdapter{lb: lb}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *LoadBalancerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	lb, ok := resource.(loadbalancers.LoadBalancer)
	if !ok {
		return fmt.Errorf("expected loadbalancers.LoadBalancer, got %T", resource)
	}
	if rule.Action == "delete" {
		if err := loadbalancers.Delete(c, lb.ID, nil).ExtractErr(); err != nil {
			return fmt.Errorf("deleting loadbalancer %s: %w", lb.ID, err)
		}
		return nil
	}
	return fmt.Errorf("octavia/loadbalancer: action %q not implemented", rule.Action)
}

type listenerAdapter struct{ l listeners.Listener }

func (a listenerAdapter) GetID() string           { return a.l.ID }
func (a listenerAdapter) GetName() string         { return a.l.Name }
func (a listenerAdapter) GetProjectID() string    { return a.l.ProjectID }
func (a listenerAdapter) GetStatus() string       { return a.l.ProvisioningStatus }
func (a listenerAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a listenerAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// ListenerAuditor audits octavia/listener resources.
//
// Allowed checks: status, exempt_names, protocol, port, tls_ciphers, has_tls_container
// age_gt is unavailable — gophercloud Listener has no CreatedAt/UpdatedAt.
//
// When protocol/port/tls atomics AND-match, observation is insecure_listener_tls (#122).
type ListenerAuditor struct{}

func (a *ListenerAuditor) ResourceType() string { return "listener" }
func (a *ListenerAuditor) ImplementedChecks() []string {
	return []string{"status", "exempt_names", "protocol", "port", "tls_ciphers", "has_tls_container"}
}

func (a *ListenerAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	l, ok := resource.(listeners.Listener)
	if !ok {
		return nil, fmt.Errorf("expected listeners.Listener, got %T", resource)
	}
	adapter := listenerAdapter{l: l}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	// Atomic AND: every specified check must match for non-compliance.
	allMatch := true
	var observations []string

	if rule.Check.Status != "" {
		if adapter.GetStatus() != rule.Check.Status {
			allMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("status=%s", adapter.GetStatus()))
		}
	}
	if rule.Check.Protocol != "" {
		if !strings.EqualFold(l.Protocol, rule.Check.Protocol) {
			allMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("protocol=%s", l.Protocol))
		}
	}
	if rule.Check.Port != 0 {
		if l.ProtocolPort != rule.Check.Port {
			allMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("port=%d", l.ProtocolPort))
		}
	}
	if rule.Check.TlsCiphers != "" {
		if l.TLSCiphers != rule.Check.TlsCiphers {
			allMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("tls_ciphers=%s", l.TLSCiphers))
		}
	}
	if rule.Check.HasTlsContainer != nil {
		hasRef := l.DefaultTlsContainerRef != ""
		if hasRef != *rule.Check.HasTlsContainer {
			allMatch = false
		} else {
			observations = append(observations, fmt.Sprintf("has_tls_container=%t", hasRef))
		}
	}

	if allMatch && len(observations) > 0 {
		result.Compliant = false
		result.Observation = insecureListenerObservation(l, observations)
	}

	return result, nil
}

func insecureListenerObservation(l listeners.Listener, observations []string) string {
	joined := strings.Join(observations, " ")
	switch {
	case strings.EqualFold(l.Protocol, "HTTP"),
		strings.EqualFold(l.Protocol, "TCP") && l.ProtocolPort == 443,
		l.DefaultTlsContainerRef == "" && strings.EqualFold(l.Protocol, "TERMINATED_HTTPS"):
		return fmt.Sprintf("insecure_listener_tls: %s", joined)
	default:
		return joined
	}
}

func (a *ListenerAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	l, ok := resource.(listeners.Listener)
	if !ok {
		return fmt.Errorf("expected listeners.Listener, got %T", resource)
	}
	if rule.Action == "delete" {
		if err := listeners.Delete(c, l.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting listener %s: %w", l.ID, err)
		}
		return nil
	}
	return fmt.Errorf("octavia/listener: action %q not implemented", rule.Action)
}

type poolAdapter struct{ p pools.Pool }

func (a poolAdapter) GetID() string           { return a.p.ID }
func (a poolAdapter) GetName() string         { return a.p.Name }
func (a poolAdapter) GetProjectID() string    { return a.p.ProjectID }
func (a poolAdapter) GetStatus() string       { return a.p.ProvisioningStatus }
func (a poolAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a poolAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// PoolAuditor audits octavia/pool resources.
// age_gt unavailable — Pool has no CreatedAt/UpdatedAt in gophercloud.
type PoolAuditor struct{}

func (a *PoolAuditor) ResourceType() string { return "pool" }
func (a *PoolAuditor) ImplementedChecks() []string {
	return []string{"status", "exempt_names", "protocol"}
}

func (a *PoolAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	p, ok := resource.(pools.Pool)
	if !ok {
		return nil, fmt.Errorf("expected pools.Pool, got %T", resource)
	}
	adapter := poolAdapter{p: p}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}
	common.CheckStatus(adapter, rule, result)
	if rule.Check.Protocol != "" && strings.EqualFold(p.Protocol, rule.Check.Protocol) {
		result.Compliant = false
		result.Observation = fmt.Sprintf("protocol=%s", p.Protocol)
	}
	return result, nil
}

func (a *PoolAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	p, ok := resource.(pools.Pool)
	if !ok {
		return fmt.Errorf("expected pools.Pool, got %T", resource)
	}
	if rule.Action == "delete" {
		if err := pools.Delete(c, p.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting pool %s: %w", p.ID, err)
		}
		return nil
	}
	return fmt.Errorf("octavia/pool: action %q not implemented", rule.Action)
}

type memberAdapter struct{ m pools.Member }

func (a memberAdapter) GetID() string           { return a.m.ID }
func (a memberAdapter) GetName() string         { return a.m.Name }
func (a memberAdapter) GetProjectID() string    { return a.m.ProjectID }
func (a memberAdapter) GetStatus() string       { return a.m.ProvisioningStatus }
func (a memberAdapter) GetCreatedAt() time.Time { return a.m.CreatedAt }
func (a memberAdapter) GetUpdatedAt() time.Time { return a.m.UpdatedAt }

// MemberAuditor audits octavia/member resources.
type MemberAuditor struct{}

func (a *MemberAuditor) ResourceType() string { return "member" }
func (a *MemberAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names", "port"}
}

func (a *MemberAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	m, ok := resource.(pools.Member)
	if !ok {
		return nil, fmt.Errorf("expected pools.Member, got %T", resource)
	}
	adapter := memberAdapter{m: m}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	if rule.Check.Port != 0 && m.ProtocolPort == rule.Check.Port {
		result.Compliant = false
		result.Observation = fmt.Sprintf("port=%d", m.ProtocolPort)
	}
	return result, nil
}

func (a *MemberAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	m, ok := resource.(pools.Member)
	if !ok {
		return fmt.Errorf("expected pools.Member, got %T", resource)
	}
	if rule.Action == "delete" {
		if m.PoolID == "" {
			return fmt.Errorf("deleting member %s: missing pool_id", m.ID)
		}
		if err := pools.DeleteMember(c, m.PoolID, m.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting member %s: %w", m.ID, err)
		}
		return nil
	}
	return fmt.Errorf("octavia/member: action %q not implemented", rule.Action)
}

type healthMonitorAdapter struct{ m monitors.Monitor }

func (a healthMonitorAdapter) GetID() string           { return a.m.ID }
func (a healthMonitorAdapter) GetName() string         { return a.m.Name }
func (a healthMonitorAdapter) GetProjectID() string    { return a.m.ProjectID }
func (a healthMonitorAdapter) GetStatus() string       { return a.m.ProvisioningStatus }
func (a healthMonitorAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a healthMonitorAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// HealthMonitorAuditor audits octavia/healthmonitor resources.
// age_gt unavailable — Monitor has no CreatedAt/UpdatedAt in gophercloud.
type HealthMonitorAuditor struct{}

func (a *HealthMonitorAuditor) ResourceType() string { return "healthmonitor" }
func (a *HealthMonitorAuditor) ImplementedChecks() []string {
	return []string{"status", "exempt_names"}
}

func (a *HealthMonitorAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	m, ok := resource.(monitors.Monitor)
	if !ok {
		return nil, fmt.Errorf("expected monitors.Monitor, got %T", resource)
	}
	adapter := healthMonitorAdapter{m: m}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}
	common.CheckStatus(adapter, rule, result)
	return result, nil
}

func (a *HealthMonitorAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	m, ok := resource.(monitors.Monitor)
	if !ok {
		return fmt.Errorf("expected monitors.Monitor, got %T", resource)
	}
	if rule.Action == "delete" {
		if err := monitors.Delete(c, m.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting healthmonitor %s: %w", m.ID, err)
		}
		return nil
	}
	return fmt.Errorf("octavia/healthmonitor: action %q not implemented", rule.Action)
}
