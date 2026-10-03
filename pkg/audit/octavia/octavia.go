package octavia
import ("context"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/policy")

type LoadBalancerAuditor struct{}
func (a *LoadBalancerAuditor) ResourceType() string { return "loadbalancer" }
func (a *LoadBalancerAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *LoadBalancerAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *LoadBalancerAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type ListenerAuditor struct{}
func (a *ListenerAuditor) ResourceType() string { return "listener" }
func (a *ListenerAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *ListenerAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ListenerAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type PoolAuditor struct{}
func (a *PoolAuditor) ResourceType() string { return "pool" }
func (a *PoolAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *PoolAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *PoolAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type MemberAuditor struct{}
func (a *MemberAuditor) ResourceType() string { return "member" }
func (a *MemberAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *MemberAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *MemberAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type HealthMonitorAuditor struct{}
func (a *HealthMonitorAuditor) ResourceType() string { return "healthmonitor" }
func (a *HealthMonitorAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *HealthMonitorAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *HealthMonitorAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }
