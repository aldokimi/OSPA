package services

import (
	"fmt"

	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/barbican"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/gophercloud/gophercloud"
)

// BarbicanService implements the Service interface for OpenStack Barbican.
//
// Supported resources:
//   - secret: Secrets
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - container: Secret containers
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - order: Orders
//     Checks: status, age_gt, exempt_names
//     Actions: log, delete, tag
type BarbicanService struct{}

func init() {
	rootservices.MustRegister(&BarbicanService{})
	rootservices.RegisterResource("barbican", "secret")
	rootservices.RegisterResource("barbican", "container")
	rootservices.RegisterResource("barbican", "order")
}

func (s *BarbicanService) Name() string {
	return "barbican"
}

func (s *BarbicanService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetBarbicanClient()
}

func (s *BarbicanService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "secret":
		return &barbican.SecretAuditor{}, nil
	case "container":
		return &barbican.ContainerAuditor{}, nil
	case "order":
		return &barbican.OrderAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *BarbicanService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "secret":
		return &discovery_services.BarbicanSecretDiscoverer{}, nil
	case "container":
		return &discovery_services.BarbicanContainerDiscoverer{}, nil
	case "order":
		return &discovery_services.BarbicanOrderDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
