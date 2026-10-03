package zaqar
import ("context"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/policy")

type QueueAuditor struct{}
func (a *QueueAuditor) ResourceType() string { return "queue" }
func (a *QueueAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *QueueAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *QueueAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type MessageAuditor struct{}
func (a *MessageAuditor) ResourceType() string { return "message" }
func (a *MessageAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *MessageAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *MessageAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type SubscriptionAuditor struct{}
func (a *SubscriptionAuditor) ResourceType() string { return "subscription" }
func (a *SubscriptionAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *SubscriptionAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *SubscriptionAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }
