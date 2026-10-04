package trove

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/db/v1/datastores"
	"github.com/gophercloud/gophercloud/openstack/db/v1/instances"
)

type instanceAdapter struct{ i instances.Instance }

func (a instanceAdapter) GetID() string           { return a.i.ID }
func (a instanceAdapter) GetName() string         { return a.i.Name }
func (a instanceAdapter) GetProjectID() string    { return "" }
func (a instanceAdapter) GetStatus() string       { return a.i.Status }
func (a instanceAdapter) GetCreatedAt() time.Time { return a.i.Created }
func (a instanceAdapter) GetUpdatedAt() time.Time { return a.i.Updated }

type InstanceAuditor struct{}

func (a *InstanceAuditor) ResourceType() string { return "instance" }
func (a *InstanceAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *InstanceAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	inst, ok := r.(instances.Instance)
	if !ok {
		return nil, fmt.Errorf("expected instances.Instance, got %T", r)
	}
	adapter := instanceAdapter{i: inst}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	// TLS/transport posture is not exposed on the Trove instance API (audit-model gap).
	return result, nil
}

func (a *InstanceAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = c
	_ = r
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/instance: action %q not implemented", rule.Action)
}

type clusterAdapter struct{ c discoveryservices.TroveCluster }

func (a clusterAdapter) GetID() string           { return a.c.ID }
func (a clusterAdapter) GetName() string         { return a.c.Name }
func (a clusterAdapter) GetProjectID() string    { return a.c.ProjectID }
func (a clusterAdapter) GetStatus() string       { return a.c.Status }
func (a clusterAdapter) GetCreatedAt() time.Time { return a.c.Created }
func (a clusterAdapter) GetUpdatedAt() time.Time { return a.c.Updated }

type ClusterAuditor struct{}

func (a *ClusterAuditor) ResourceType() string { return "cluster" }
func (a *ClusterAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ClusterAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	cl, ok := r.(discoveryservices.TroveCluster)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.TroveCluster, got %T", r)
	}
	adapter := clusterAdapter{c: cl}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *ClusterAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = c
	_ = r
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/cluster: action %q not implemented", rule.Action)
}

type backupAdapter struct{ b discoveryservices.TroveBackup }

func (a backupAdapter) GetID() string           { return a.b.ID }
func (a backupAdapter) GetName() string         { return a.b.Name }
func (a backupAdapter) GetProjectID() string    { return a.b.ProjectID }
func (a backupAdapter) GetStatus() string       { return a.b.Status }
func (a backupAdapter) GetCreatedAt() time.Time { return a.b.Created }
func (a backupAdapter) GetUpdatedAt() time.Time { return a.b.Updated }

type BackupAuditor struct{}

func (a *BackupAuditor) ResourceType() string { return "backup" }
func (a *BackupAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names", "backup_retention_days"}
}

func (a *BackupAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	b, ok := r.(discoveryservices.TroveBackup)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.TroveBackup, got %T", r)
	}
	adapter := backupAdapter{b: b}
	result := common.BuildBaseResult(adapter, rule)

	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}

	if err := common.CheckAgeGT(adapter, rule, result); err != nil {
		return nil, err
	}

	if rule.Check.BackupRetentionDays > 0 {
		ts := b.Updated
		if ts.IsZero() {
			ts = b.Created
		}
		if !ts.IsZero() {
			maxAge := time.Duration(rule.Check.BackupRetentionDays) * 24 * time.Hour
			if time.Since(ts) > maxAge {
				result.Compliant = false
				result.Observation = fmt.Sprintf(
					"backup_retention_exceeded: backup older than %d days (last updated: %s)",
					rule.Check.BackupRetentionDays, ts.Format(time.RFC3339),
				)
			}
		}
	}

	return result, nil
}

func (a *BackupAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = c
	_ = r
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/backup: action %q not implemented", rule.Action)
}

type datastoreAdapter struct{ d datastores.Datastore }

func (a datastoreAdapter) GetID() string           { return a.d.Name }
func (a datastoreAdapter) GetName() string         { return a.d.Name }
func (a datastoreAdapter) GetProjectID() string    { return "" }
func (a datastoreAdapter) GetStatus() string       { return "" }
func (a datastoreAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a datastoreAdapter) GetUpdatedAt() time.Time { return time.Time{} }

type DatastoreAuditor struct{}

func (a *DatastoreAuditor) ResourceType() string { return "datastore" }
func (a *DatastoreAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *DatastoreAuditor) Check(ctx context.Context, r interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	ds, ok := r.(datastores.Datastore)
	if !ok {
		return nil, fmt.Errorf("expected datastores.Datastore, got %T", r)
	}
	adapter := datastoreAdapter{d: ds}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}
	return result, nil
}

func (a *DatastoreAuditor) Fix(ctx context.Context, c interface{}, r interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = c
	_ = r
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/datastore: action %q not implemented", rule.Action)
}
