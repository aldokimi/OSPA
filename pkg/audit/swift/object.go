package swift

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
)

type objectAdapter struct {
	o discoveryservices.ObjectWithContainer
}

func (a objectAdapter) GetID() string           { return a.o.ContainerName + "/" + a.o.Name }
func (a objectAdapter) GetName() string         { return a.o.Name }
func (a objectAdapter) GetProjectID() string    { return "" } // already scoped to the authenticated project
func (a objectAdapter) GetStatus() string       { return "" } // objects have no status
func (a objectAdapter) GetCreatedAt() time.Time { return a.o.LastModified }
func (a objectAdapter) GetUpdatedAt() time.Time { return a.o.LastModified }

// ObjectAuditor audits swift/object resources.
//
// Allowed checks: age_gt, exempt_names
// Allowed actions: log, delete, tag
//
// Note: gophercloud's Object struct has no status field and no concept of
// "unused" beyond size, so only age_gt (backed by LastModified) and
// exempt_names apply.
type ObjectAuditor struct{}

func (a *ObjectAuditor) ResourceType() string {
	return "object"
}

func (a *ObjectAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names"}
}

func (a *ObjectAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	o, ok := resource.(discoveryservices.ObjectWithContainer)
	if !ok {
		return nil, fmt.Errorf("expected discoveryservices.ObjectWithContainer, got %T", resource)
	}

	adapter := objectAdapter{o: o}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	return result, nil
}

func (a *ObjectAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	o, ok := resource.(discoveryservices.ObjectWithContainer)
	if !ok {
		return fmt.Errorf("expected discoveryservices.ObjectWithContainer, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if res := objects.Delete(c, o.ContainerName, o.Name, objects.DeleteOpts{}); res.Err != nil {
			return fmt.Errorf("deleting object %s/%s: %w", o.ContainerName, o.Name, res.Err)
		}
		return nil

	case "tag":
		return fmt.Errorf("swift/object: tag action not yet implemented")

	default:
		return fmt.Errorf("swift/object: action %q not implemented", rule.Action)
	}
}
