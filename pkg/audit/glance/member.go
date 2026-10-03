package glance

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

type memberAdapter struct{ m members.Member }

func (a memberAdapter) GetID() string           { return fmt.Sprintf("%s/%s", a.m.ImageID, a.m.MemberID) }
func (a memberAdapter) GetName() string         { return a.m.MemberID } // members have no display name
func (a memberAdapter) GetProjectID() string    { return a.m.MemberID }
func (a memberAdapter) GetStatus() string       { return a.m.Status }
func (a memberAdapter) GetCreatedAt() time.Time { return a.m.CreatedAt }
func (a memberAdapter) GetUpdatedAt() time.Time { return a.m.UpdatedAt }

// MemberAuditor audits glance/member resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: a member has no display name of its own, so exempt_names matches
// against the member (project) ID instead.
type MemberAuditor struct{}

func (a *MemberAuditor) ResourceType() string {
	return "member"
}

func (a *MemberAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *MemberAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	m, ok := resource.(members.Member)
	if !ok {
		return nil, fmt.Errorf("expected members.Member, got %T", resource)
	}

	adapter := memberAdapter{m: m}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && m.Status == "pending" {
		result.Compliant = false
		result.Observation = "member share has been pending acceptance"
	}

	return result, nil
}

func (a *MemberAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	m, ok := resource.(members.Member)
	if !ok {
		return fmt.Errorf("expected members.Member, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := members.Delete(c, m.ImageID, m.MemberID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting member %s from image %s: %w", m.MemberID, m.ImageID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("glance/member: tag action not yet implemented")

	default:
		return fmt.Errorf("glance/member: action %q not implemented", rule.Action)
	}
}
