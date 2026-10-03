package cinder

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/extensions/backups"
)

type backupAdapter struct{ b backups.Backup }

func (a backupAdapter) GetID() string           { return a.b.ID }
func (a backupAdapter) GetName() string         { return a.b.Name }
func (a backupAdapter) GetProjectID() string    { return a.b.ProjectID }
func (a backupAdapter) GetStatus() string       { return a.b.Status }
func (a backupAdapter) GetCreatedAt() time.Time { return a.b.CreatedAt }
func (a backupAdapter) GetUpdatedAt() time.Time { return a.b.UpdatedAt }

// BackupAuditor audits cinder/backup resources.
//
// Allowed checks: status, age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: backups are point-in-time copies rather than live resources, so
// "unused" has no natural meaning here and is intentionally not offered.
type BackupAuditor struct{}

func (a *BackupAuditor) ResourceType() string {
	return "backup"
}

func (a *BackupAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "exempt_names"}
}

func (a *BackupAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	b, ok := resource.(backups.Backup)
	if !ok {
		return nil, fmt.Errorf("expected backups.Backup, got %T", resource)
	}

	adapter := backupAdapter{b: b}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
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

	b, ok := resource.(backups.Backup)
	if !ok {
		return fmt.Errorf("expected backups.Backup, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if b.HasDependentBackups {
			return fmt.Errorf("cannot delete backup %s: has dependent backups", b.ID)
		}
		if err := backups.Delete(c, b.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting backup %s: %w", b.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("cinder/backup: tag action not yet implemented")

	default:
		return fmt.Errorf("cinder/backup: action %q not implemented", rule.Action)
	}
}
