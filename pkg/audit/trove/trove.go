package trove

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
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

// InstanceAuditor audits trove/instance resources.
//
// TLS/transport security is not exposed on the instance list/detail payload
// in gophercloud — treat as API-audit model availability gap (#121).
type InstanceAuditor struct{}

func (a *InstanceAuditor) ResourceType() string { return "instance" }
func (a *InstanceAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *InstanceAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	i, ok := resource.(instances.Instance)
	if !ok {
		return nil, fmt.Errorf("expected instances.Instance, got %T", resource)
	}
	adapter := instanceAdapter{i: i}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *InstanceAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	i, ok := resource.(instances.Instance)
	if !ok {
		return fmt.Errorf("expected instances.Instance, got %T", resource)
	}
	if rule.Action == "delete" {
		if err := instances.Delete(c, i.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting trove instance %s: %w", i.ID, err)
		}
		return nil
	}
	return fmt.Errorf("trove/instance: action %q not implemented", rule.Action)
}

type clusterAdapter struct {
	c discoveryservices.TroveCluster
}

func (a clusterAdapter) GetID() string           { return a.c.ID }
func (a clusterAdapter) GetName() string         { return a.c.Name }
func (a clusterAdapter) GetProjectID() string    { return "" }
func (a clusterAdapter) GetStatus() string       { return a.c.Status }
func (a clusterAdapter) GetCreatedAt() time.Time { return a.c.CreatedAt }
func (a clusterAdapter) GetUpdatedAt() time.Time { return a.c.UpdatedAt }

type ClusterAuditor struct{}

func (a *ClusterAuditor) ResourceType() string { return "cluster" }
func (a *ClusterAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *ClusterAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	c, ok := resource.(discoveryservices.TroveCluster)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.TroveCluster, got %T", resource)
	}
	adapter := clusterAdapter{c: c}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	return result, nil
}

func (a *ClusterAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/cluster: action %q not implemented", rule.Action)
}

type backupAdapter struct{ b discoveryservices.TroveBackup }

func (a backupAdapter) GetID() string           { return a.b.ID }
func (a backupAdapter) GetName() string         { return a.b.Name }
func (a backupAdapter) GetProjectID() string    { return "" }
func (a backupAdapter) GetStatus() string       { return a.b.Status }
func (a backupAdapter) GetCreatedAt() time.Time { return a.b.CreatedAt }
func (a backupAdapter) GetUpdatedAt() time.Time { return a.b.UpdatedAt }

// BackupAuditor audits trove/backup resources.
//
// Retention compliance is expressed via age_gt; matches emit
// backup_retention_exceeded observations (#121).
type BackupAuditor struct{}

func (a *BackupAuditor) ResourceType() string { return "backup" }
func (a *BackupAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names", "status"}
}

func (a *BackupAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	b, ok := resource.(discoveryservices.TroveBackup)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.TroveBackup, got %T", resource)
	}
	adapter := backupAdapter{b: b}
	result := common.BuildBaseResult(adapter, rule)
	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}
	if !result.Compliant && rule.Check.AgeGT != "" {
		result.Observation = fmt.Sprintf(
			"backup_retention_exceeded: backup %q older than %s (instance_id=%s; no dedicated retention field in API)",
			b.Name, rule.Check.AgeGT, b.InstanceID,
		)
	}
	return result, nil
}

func (a *BackupAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	if rule.Action == "log" {
		return nil
	}
	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}
	b, ok := resource.(discoveryservices.TroveBackup)
	if !ok {
		return fmt.Errorf("expected discoveryservices.TroveBackup, got %T", resource)
	}
	if rule.Action == "delete" {
		resp, err := c.Request("DELETE", c.ServiceURL("backups", b.ID), &gophercloud.RequestOpts{
			OkCodes: []int{202, 204},
		})
		if err != nil {
			return fmt.Errorf("deleting trove backup %s: %w", b.ID, err)
		}
		_ = resp.Body.Close()
		return nil
	}
	return fmt.Errorf("trove/backup: action %q not implemented", rule.Action)
}

type datastoreAdapter struct{ d datastores.Datastore }

func (a datastoreAdapter) GetID() string           { return a.d.ID }
func (a datastoreAdapter) GetName() string         { return a.d.Name }
func (a datastoreAdapter) GetProjectID() string    { return "" }
func (a datastoreAdapter) GetStatus() string       { return "" }
func (a datastoreAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a datastoreAdapter) GetUpdatedAt() time.Time { return time.Time{} }

type DatastoreAuditor struct{}

func (a *DatastoreAuditor) ResourceType() string { return "datastore" }
func (a *DatastoreAuditor) ImplementedChecks() []string {
	return []string{"exempt_names"}
}

func (a *DatastoreAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx
	d, ok := resource.(datastores.Datastore)
	if !ok {
		return nil, fmt.Errorf("expected datastores.Datastore, got %T", resource)
	}
	adapter := datastoreAdapter{d: d}
	result := common.BuildBaseResult(adapter, rule)
	if common.CheckExemptByName(adapter, rule, result) {
		return result, nil
	}
	// Datastores have no timestamps/status in the list API — age_gt/status are not meaningful.
	return result, nil
}

func (a *DatastoreAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx
	_ = client
	_ = resource
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("trove/datastore: action %q not implemented", rule.Action)
}
