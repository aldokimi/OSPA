package cinder

import (
	"context"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/extensions/backups"
)

func TestBackupAuditor_ResourceType(t *testing.T) {
	auditor := &BackupAuditor{}
	if got := auditor.ResourceType(); got != "backup" {
		t.Errorf("ResourceType() = %q, want %q", got, "backup")
	}
}

func TestBackupAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &BackupAuditor{}
	b := backups.Backup{ID: "bkp-123", Name: "test-backup", Status: "error", ProjectID: "proj-456"}

	rule := &policy.Rule{
		Name:  "find-error-backups",
		Check: policy.CheckConditions{Status: "error"},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for error backup")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestBackupAuditor_Check_ExemptName(t *testing.T) {
	auditor := &BackupAuditor{}
	b := backups.Backup{ID: "bkp-123", Name: "default", Status: "error"}

	rule := &policy.Rule{
		Name:  "find-error-backups",
		Check: policy.CheckConditions{Status: "error", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), b, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt backup")
	}
}

func TestBackupAuditor_Check_InvalidType(t *testing.T) {
	auditor := &BackupAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-backup", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestBackupAuditor_Fix_Log(t *testing.T) {
	auditor := &BackupAuditor{}
	b := backups.Backup{ID: "bkp-123"}
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, b, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestBackupAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &BackupAuditor{}
	b := backups.Backup{ID: "bkp-123"}
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, b, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestBackupAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &BackupAuditor{}
	b := backups.Backup{ID: "bkp-123"}
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, b, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
