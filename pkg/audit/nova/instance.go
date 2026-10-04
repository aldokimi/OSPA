package nova

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

type instanceAdapter struct{ s servers.Server }

func (a instanceAdapter) GetID() string           { return a.s.ID }
func (a instanceAdapter) GetName() string         { return a.s.Name }
func (a instanceAdapter) GetProjectID() string    { return a.s.TenantID }
func (a instanceAdapter) GetStatus() string       { return a.s.Status }
func (a instanceAdapter) GetCreatedAt() time.Time { return a.s.Created }
func (a instanceAdapter) GetUpdatedAt() time.Time { return a.s.Updated }

// InstanceAuditor audits nova/instance resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, image_name, no_keypair
// Allowed actions: log, delete, tag
type InstanceAuditor struct{}

func (a *InstanceAuditor) ResourceType() string {
	return "instance"
}

func (a *InstanceAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "image_name", "no_keypair"}
}

func (a *InstanceAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(servers.Server)
	if !ok {
		return nil, fmt.Errorf("expected servers.Server, got %T", resource)
	}

	adapter := instanceAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	idleHit := false
	if rule.Check.Unused && s.Status == "SHUTOFF" {
		idleHit = true
		result.Compliant = false
		result.Observation = "instance is stopped but still allocated (SHUTOFF)"
	}

	if len(rule.Check.ImageName) > 0 {
		imageID, _ := s.Image["id"].(string)
		for _, banned := range rule.Check.ImageName {
			if imageID == banned {
				result.Compliant = false
				result.Observation = fmt.Sprintf("instance uses a deprecated or banned image (%s)", imageID)
				break
			}
		}
	}

	noKeyHit := false
	if rule.Check.NoKeypair && s.KeyName == "" {
		noKeyHit = true
		result.Compliant = false
		result.Observation = "instance has no SSH keypair attached"
	}

	// #108 catalog outcome: idle/SHUTOFF + missing keypair.
	if idleHit && noKeyHit {
		result.Observation = "idle_no_keypair: instance is SHUTOFF and has no SSH keypair attached"
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

	s, ok := resource.(servers.Server)
	if !ok {
		return fmt.Errorf("expected servers.Server, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := servers.Delete(c, s.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting instance %s: %w", s.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("nova/instance: tag action not yet implemented")

	default:
		return fmt.Errorf("nova/instance: action %q not implemented", rule.Action)
	}
}
