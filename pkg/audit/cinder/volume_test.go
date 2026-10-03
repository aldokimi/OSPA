package cinder

import (
	"context"
	"testing"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/volumes"
)

func TestVolumeAuditor_ResourceType(t *testing.T) {
	auditor := &VolumeAuditor{}
	if got := auditor.ResourceType(); got != "volume" {
		t.Errorf("ResourceType() = %q, want %q", got, "volume")
	}
}

func newVolume(overrides func(*discoveryservices.VolumeWithTenant)) discoveryservices.VolumeWithTenant {
	v := discoveryservices.VolumeWithTenant{
		Volume: volumes.Volume{ID: "vol-123", Name: "test-volume", Status: "available"},
	}
	v.TenantID = "proj-456"
	if overrides != nil {
		overrides(&v)
	}
	return v
}

func TestVolumeAuditor_Check_StatusMatch(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(func(v *discoveryservices.VolumeWithTenant) { v.Status = "error" })

	rule := &policy.Rule{
		Name:  "find-error-volumes",
		Check: policy.CheckConditions{Status: "error"},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for error volume")
	}
	if result.ProjectID != "proj-456" {
		t.Errorf("ProjectID = %q, want %q", result.ProjectID, "proj-456")
	}
}

func TestVolumeAuditor_Check_Unused(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(nil)

	rule := &policy.Rule{
		Name:  "find-unused-volumes",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for unattached volume")
	}
}

func TestVolumeAuditor_Check_Attached(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(func(v *discoveryservices.VolumeWithTenant) {
		v.Attachments = []volumes.Attachment{{ServerID: "srv-1"}}
	})

	rule := &policy.Rule{
		Name:  "find-unattached-volumes",
		Check: policy.CheckConditions{Unused: true},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for attached volume when checking unused")
	}
}

func TestVolumeAuditor_Check_Encrypted(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(func(v *discoveryservices.VolumeWithTenant) { v.Encrypted = false })

	want := true
	rule := &policy.Rule{
		Name:  "require-encrypted-volumes",
		Check: policy.CheckConditions{Encrypted: &want},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for unencrypted volume when encryption is required")
	}
}

func TestVolumeAuditor_Check_HasBackup(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(nil)

	want := true
	rule := &policy.Rule{
		Name:  "require-backed-up-volumes",
		Check: policy.CheckConditions{HasBackup: &want},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Error("Check() expected non-compliant for volume with no backup")
	}
}

func TestVolumeAuditor_Check_ExemptName(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(func(v *discoveryservices.VolumeWithTenant) {
		v.Name = "default"
		v.Status = "error"
	})

	rule := &policy.Rule{
		Name:  "find-error-volumes",
		Check: policy.CheckConditions{Status: "error", ExemptNames: []string{"default"}},
	}

	result, err := auditor.Check(context.Background(), v, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Compliant {
		t.Error("Check() expected compliant for exempt volume")
	}
}

func TestVolumeAuditor_Check_InvalidType(t *testing.T) {
	auditor := &VolumeAuditor{}

	_, err := auditor.Check(context.Background(), "not-a-volume", &policy.Rule{})
	if err == nil {
		t.Error("Check() expected error for invalid resource type")
	}
}

func TestVolumeAuditor_Fix_Log(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(nil)
	rule := &policy.Rule{Action: "log"}

	if err := auditor.Fix(context.Background(), nil, v, rule); err != nil {
		t.Errorf("Fix(log) error = %v, want nil", err)
	}
}

func TestVolumeAuditor_Fix_Delete_RequiresClient(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(nil)
	rule := &policy.Rule{Action: "delete"}

	if err := auditor.Fix(context.Background(), nil, v, rule); err == nil {
		t.Error("Fix(delete) expected error without client")
	}
}

func TestVolumeAuditor_Fix_UnsupportedAction(t *testing.T) {
	auditor := &VolumeAuditor{}
	v := newVolume(nil)
	rule := &policy.Rule{Action: "reboot"}

	if err := auditor.Fix(context.Background(), nil, v, rule); err == nil {
		t.Error("Fix(reboot) expected error for unsupported action")
	}
}
