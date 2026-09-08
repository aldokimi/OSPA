package barbican

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
)

type secretAdapter struct{ s secrets.Secret }

func (a secretAdapter) GetID() string           { return discoveryservices.BarbicanRefID(a.s.SecretRef) }
func (a secretAdapter) GetName() string         { return a.s.Name }
func (a secretAdapter) GetProjectID() string    { return "" } // not exposed on the secret resource itself
func (a secretAdapter) GetStatus() string       { return a.s.Status }
func (a secretAdapter) GetCreatedAt() time.Time { return a.s.Created }
func (a secretAdapter) GetUpdatedAt() time.Time { return a.s.Updated }

// SecretAuditor audits barbican/secret resources.
//
// Allowed checks: status, age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
type SecretAuditor struct{}

func (a *SecretAuditor) ResourceType() string {
	return "secret"
}

func (a *SecretAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names"}
}

func (a *SecretAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	s, ok := resource.(secrets.Secret)
	if !ok {
		return nil, fmt.Errorf("expected secrets.Secret, got %T", resource)
	}

	adapter := secretAdapter{s: s}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && !s.Expiration.IsZero() && time.Now().After(s.Expiration) {
		result.Compliant = false
		result.Observation = fmt.Sprintf("secret expired at %s", s.Expiration.Format(time.RFC3339))
	}

	return result, nil
}

func (a *SecretAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	s, ok := resource.(secrets.Secret)
	if !ok {
		return fmt.Errorf("expected secrets.Secret, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		id := discoveryservices.BarbicanRefID(s.SecretRef)
		if err := secrets.Delete(c, id).ExtractErr(); err != nil {
			return fmt.Errorf("deleting secret %s: %w", id, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("barbican/secret: tag action not yet implemented")

	default:
		return fmt.Errorf("barbican/secret: action %q not implemented", rule.Action)
	}
}
