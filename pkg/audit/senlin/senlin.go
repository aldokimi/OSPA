package senlin
import ("context"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/policy")

type ClusterAuditor struct{}
func (a *ClusterAuditor) ResourceType() string { return "cluster" }
func (a *ClusterAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *ClusterAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ClusterAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type ProfileAuditor struct{}
func (a *ProfileAuditor) ResourceType() string { return "profile" }
func (a *ProfileAuditor) ImplementedChecks() []string { return []string{"age_gt","exempt_names"} }
func (a *ProfileAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ProfileAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type NodeAuditor struct{}
func (a *NodeAuditor) ResourceType() string { return "node" }
func (a *NodeAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *NodeAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *NodeAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type PolicyAuditor struct{}
func (a *PolicyAuditor) ResourceType() string { return "policy" }
func (a *PolicyAuditor) ImplementedChecks() []string { return []string{"age_gt","exempt_names"} }
func (a *PolicyAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *PolicyAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }
