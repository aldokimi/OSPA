package nova

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
)

type keypairAdapter struct{ k keypairs.KeyPair }

func (a keypairAdapter) GetID() string           { return a.k.Name }
func (a keypairAdapter) GetName() string         { return a.k.Name }
func (a keypairAdapter) GetProjectID() string    { return "" } // keypairs are user-scoped, not project-scoped
func (a keypairAdapter) GetStatus() string       { return "" } // keypairs have no status
func (a keypairAdapter) GetCreatedAt() time.Time { return time.Time{} }
func (a keypairAdapter) GetUpdatedAt() time.Time { return time.Time{} }

// KeypairAuditor audits nova/keypair resources.
//
// Allowed checks: age_gt, unused, exempt_names
// Allowed actions: log, delete, tag
//
// Note: gophercloud's keypairs.KeyPair has no timestamp fields, so age_gt
// is accepted for policy consistency but is a no-op. Determining whether a
// keypair is actually attached to any instance requires enumerating all
// servers, which Check() cannot do without a client; unused is likewise
// accepted but left as a pending observation.
type KeypairAuditor struct{}

func (a *KeypairAuditor) ResourceType() string {
	return "keypair"
}

func (a *KeypairAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "unused", "exempt_names"}
}

func (a *KeypairAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	k, ok := resource.(keypairs.KeyPair)
	if !ok {
		return nil, fmt.Errorf("expected keypairs.KeyPair, got %T", resource)
	}

	adapter := keypairAdapter{k: k}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused {
		result.Observation = "unused check pending - requires instance enumeration"
	}

	return result, nil
}

func (a *KeypairAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	k, ok := resource.(keypairs.KeyPair)
	if !ok {
		return fmt.Errorf("expected keypairs.KeyPair, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if err := keypairs.Delete(c, k.Name, keypairs.DeleteOpts{}).ExtractErr(); err != nil {
			return fmt.Errorf("deleting keypair %s: %w", k.Name, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("nova/keypair: tag action not yet implemented")

	default:
		return fmt.Errorf("nova/keypair: action %q not implemented", rule.Action)
	}
}
