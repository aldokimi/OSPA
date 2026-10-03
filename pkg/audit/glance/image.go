package glance

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
)

type imageAdapter struct{ img images.Image }

func (a imageAdapter) GetID() string           { return a.img.ID }
func (a imageAdapter) GetName() string         { return a.img.Name }
func (a imageAdapter) GetProjectID() string    { return a.img.Owner }
func (a imageAdapter) GetStatus() string       { return string(a.img.Status) }
func (a imageAdapter) GetCreatedAt() time.Time { return a.img.CreatedAt }
func (a imageAdapter) GetUpdatedAt() time.Time { return a.img.UpdatedAt }

// ImageAuditor audits glance/image resources.
//
// Allowed checks: status, age_gt, unused, exempt_names, visibility
// Allowed actions: log, delete, tag
type ImageAuditor struct{}

func (a *ImageAuditor) ResourceType() string {
	return "image"
}

func (a *ImageAuditor) ImplementedChecks() []string {
	return []string{"status", "age_gt", "unused", "exempt_names", "visibility"}
}

func (a *ImageAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	img, ok := resource.(images.Image)
	if !ok {
		return nil, fmt.Errorf("expected images.Image, got %T", resource)
	}

	adapter := imageAdapter{img: img}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	if rule.Check.Unused && img.Hidden {
		result.Compliant = false
		result.Observation = "image is hidden from the default listing but still consuming storage"
	}

	if rule.Check.Visibility != "" && string(img.Visibility) == rule.Check.Visibility {
		result.Compliant = false
		result.Observation = fmt.Sprintf("image visibility is %s", img.Visibility)
	}

	return result, nil
}

func (a *ImageAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	img, ok := resource.(images.Image)
	if !ok {
		return fmt.Errorf("expected images.Image, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		if img.Protected {
			return fmt.Errorf("cannot delete image %s: protected", img.ID)
		}
		if err := images.Delete(c, img.ID).ExtractErr(); err != nil {
			return fmt.Errorf("deleting image %s: %w", img.ID, err)
		}
		return nil

	case "tag":
		return fmt.Errorf("glance/image: tag action not yet implemented")

	default:
		return fmt.Errorf("glance/image: action %q not implemented", rule.Action)
	}
}
