package cinder

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/volumes"
)

type volumeAdapter struct {
	v discoveryservices.VolumeWithTenant
}

func (a volumeAdapter) GetID() string           { return a.v.ID }
func (a volumeAdapter) GetName() string         { return a.v.Name }
func (a volumeAdapter) GetProjectID() string    { return a.v.TenantID }
func (a volumeAdapter) GetStatus() string       { return a.v.Status }
func (a volumeAdapter) GetCreatedAt() time.Time { return a.v.CreatedAt }
func (a volumeAdapter) GetUpdatedAt() time.Time { return a.v.UpdatedAt }

// VolumeAuditor audits cinder/volume resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, encrypted, attached, has_backup
// Allowed actions: log, delete, tag
type VolumeAuditor struct{}

func (a *VolumeAuditor) ResourceType() string {
	return "volume"
}

func (a *VolumeAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "encrypted", "attached", "has_backup"}
}

func (a *VolumeAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	v, ok := resource.(discoveryservices.VolumeWithTenant)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.VolumeWithTenant, got %T", resource)
	}

	adapter := volumeAdapter{v: v}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	attached := len(v.Attachments) > 0

	if rule.Check.Unused && attached {
		result.Compliant = true
	} else if rule.Check.Unused && !attached {
		result.Compliant = false
		result.Observation = "volume is not attached to any instance"
	}

	if rule.Check.Attached != nil && attached != *rule.Check.Attached {
		result.Compliant = false
		result.Observation = "volume is not attached to any instance"
	}

	if rule.Check.Encrypted != nil && v.Encrypted != *rule.Check.Encrypted {
		result.Compliant = false
		result.Observation = "volume is not encrypted"
	}

	if rule.Check.HasBackup != nil {
		hasBackup := v.BackupID != nil && *v.BackupID != ""
		if hasBackup != *rule.Check.HasBackup {
			result.Compliant = false
			result.Observation = "volume has no backup"
		}
	}

	return result, nil
}

func (a *VolumeAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	v, ok := resource.(discoveryservices.VolumeWithTenant)
	if !ok {
		return fmt.Errorf("expected discoveryservices.VolumeWithTenant, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if len(v.Attachments) > 0 {
			return fmt.Errorf("cannot delete volume %s: still attached to an instance", v.ID)
		}
		if err := volumes.Delete(c, v.ID, volumes.DeleteOpts{}).ExtractErr(); err != nil {
			return fmt.Errorf("deleting volume %s: %w", v.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("cinder/volume: tag action not yet implemented")

	default:
		return fmt.Errorf("cinder/volume: action %q not implemented", rule.Action)
	}
}
