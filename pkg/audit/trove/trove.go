package trove
import ("context"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"; "github.com/OpenStack-Policy-Agent/OSPA/pkg/policy")

type InstanceAuditor struct{}
func (a *InstanceAuditor) ResourceType() string { return "instance" }
func (a *InstanceAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *InstanceAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *InstanceAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type ClusterAuditor struct{}
func (a *ClusterAuditor) ResourceType() string { return "cluster" }
func (a *ClusterAuditor) ImplementedChecks() []string { return []string{"status","age_gt","exempt_names"} }
func (a *ClusterAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *ClusterAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type BackupAuditor struct{}
func (a *BackupAuditor) ResourceType() string { return "backup" }
func (a *BackupAuditor) ImplementedChecks() []string { return []string{"age_gt","exempt_names"} }
func (a *BackupAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *BackupAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }

type DatastoreAuditor struct{}
func (a *DatastoreAuditor) ResourceType() string { return "datastore" }
func (a *DatastoreAuditor) ImplementedChecks() []string { return []string{"age_gt","exempt_names"} }
func (a *DatastoreAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) { return &audit.Result{}, nil }
func (a *DatastoreAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error { return nil }
