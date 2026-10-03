package services

import (
	"fmt"

	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/glance"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/gophercloud/gophercloud"
)

// GlanceService implements the Service interface for OpenStack Glance.
//
// Supported resources:
//   - image: Images
//     Checks: status, age_gt, unused, exempt_names, visibility
//     Actions: log, delete, tag
//   - member: Image members
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
type GlanceService struct{}

func init() {
	rootservices.MustRegister(&GlanceService{})
	rootservices.RegisterResource("glance", "image")
	rootservices.RegisterResource("glance", "member")
}

func (s *GlanceService) Name() string {
	return "glance"
}

func (s *GlanceService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetGlanceClient()
}

func (s *GlanceService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "image":
		return &glance.ImageAuditor{}, nil
	case "member":
		return &glance.MemberAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *GlanceService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "image":
		return &discovery_services.GlanceImageDiscoverer{}, nil
	case "member":
		return &discovery_services.GlanceMemberDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
