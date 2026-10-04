package barbican

import (
	"context"
	"fmt"
	"strings"
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
// Allowed checks: status, age_gt, unused, exempt_names, secret_type, secret_risk
// Allowed actions: log, delete, tag
//
// #100: when age_gt matches (optionally filtered by secret_type), observations
// use the stale_secret_material semantic outcome. Barbican has no dedicated
// "last rotated" field — freshness uses Updated/Created timestamps.
type SecretAuditor struct{}

func (a *SecretAuditor) ResourceType() string {
	return "secret"
}

func (a *SecretAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "secret_type", "secret_risk"}
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

	if rule.Check.SecretType != "" && !strings.EqualFold(s.SecretType, rule.Check.SecretType) {
		// AND semantics: type filter missed — do not flag (clear age/status hits).
		result.Compliant = true
		result.Observation = ""
		return result, nil
	}

	if rule.Check.Unused && !s.Expiration.IsZero() && time.Now().After(s.Expiration) {
		result.Compliant = false
		result.Observation = fmt.Sprintf("secret expired at %s", s.Expiration.Format(time.RFC3339))
	}

	// secret_type alone (no other matching domain checks yet) flags the type.
	if rule.Check.SecretType != "" && result.Compliant &&
		rule.Check.Status == "" && rule.Check.AgeGT == "" && !rule.Check.Unused {
		result.Compliant = false
		result.Observation = fmt.Sprintf("secret_type=%s", s.SecretType)
	}

	riskHit := false
	if rule.Check.SecretRisk != "" {
		risk := classifySecretRisk(s.SecretType)
		if !strings.EqualFold(risk, rule.Check.SecretRisk) {
			// AND semantics: risk filter missed — clear other hits.
			result.Compliant = true
			result.Observation = ""
			return result, nil
		}
		riskHit = true
		if result.Compliant {
			result.Compliant = false
			result.Observation = fmt.Sprintf("secret_risk=%s (secret_type=%s)", risk, s.SecretType)
		}
	}

	// #119 catalog outcome: high-risk stale material (extends #100).
	if !result.Compliant && rule.Check.AgeGT != "" && (riskHit || classifySecretRisk(s.SecretType) == "high") {
		ts := s.Updated
		if ts.IsZero() {
			ts = s.Created
		}
		typeLabel := s.SecretType
		if typeLabel == "" {
			typeLabel = "unknown"
		}
		risk := classifySecretRisk(s.SecretType)
		if risk == "high" || rule.Check.SecretRisk != "" {
			result.Observation = fmt.Sprintf(
				"high_risk_stale_secret: secret_risk=%q secret_type=%q older than %s (last updated: %s; no rotation metadata in API)",
				risk, typeLabel, rule.Check.AgeGT, ts.Format(time.RFC3339),
			)
			return result, nil
		}
	}

	// #100 semantic outcome: age-based freshness risk (no rotation metadata in API).
	if !result.Compliant && rule.Check.AgeGT != "" {
		ts := s.Updated
		if ts.IsZero() {
			ts = s.Created
		}
		typeLabel := s.SecretType
		if typeLabel == "" {
			typeLabel = "unknown"
		}
		result.Observation = fmt.Sprintf(
			"stale_secret_material: secret_type=%q older than %s (last updated: %s; no rotation metadata in API)",
			typeLabel, rule.Check.AgeGT, ts.Format(time.RFC3339),
		)
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
