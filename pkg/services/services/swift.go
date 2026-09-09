package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/swift"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// SwiftService implements the Service interface for OpenStack Swift.
//
// Supported resources:
//   - account: singleton per-project storage account (read-only)
//     Checks: quota_set
//     Actions: log
//   - container: Containers
//     Checks: unused, exempt_names
//     Actions: log, delete, tag
//   - object: Objects
//     Checks: age_gt, exempt_names
//     Actions: log, delete, tag
type SwiftService struct{}

func init() {
	rootservices.MustRegister(&SwiftService{})
	rootservices.RegisterResource("swift", "account")
	rootservices.RegisterResource("swift", "container")
	rootservices.RegisterResource("swift", "object")
}

func (s *SwiftService) Name() string {
	return "swift"
}

func (s *SwiftService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetSwiftClient()
}

func (s *SwiftService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "account":
		return &swift.AccountAuditor{}, nil
	case "container":
		return &swift.ContainerAuditor{}, nil
	case "object":
		return &swift.ObjectAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *SwiftService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "account":
		return &discovery_services.SwiftAccountDiscoverer{}, nil
	case "container":
		return &discovery_services.SwiftContainerDiscoverer{}, nil
	case "object":
		return &discovery_services.SwiftObjectDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
