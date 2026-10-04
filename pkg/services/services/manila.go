package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/manila"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// ManillaService implements the Service interface for OpenStack Manila.
type ManillaService struct{}

func init() {
	rootservices.MustRegister(&ManillaService{})
	rootservices.RegisterResource("manila", "share")
	rootservices.RegisterResource("manila", "share_snapshot")
	rootservices.RegisterResource("manila", "share_network")
	rootservices.RegisterResource("manila", "share_server")
}

func (s *ManillaService) Name() string { return "manila" }

func (s *ManillaService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetManilaClient()
}

func (s *ManillaService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "share":
		return &manila.ShareAuditor{}, nil
	case "share_snapshot":
		return &manila.ShareSnapshotAuditor{}, nil
	case "share_network":
		return &manila.ShareNetworkAuditor{}, nil
	case "share_server":
		return &manila.ShareServerAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *ManillaService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "share":
		return &discovery_services.ManillaShareDiscoverer{}, nil
	case "share_snapshot":
		return &discovery_services.ManillaShareSnapshotDiscoverer{}, nil
	case "share_network":
		return &discovery_services.ManillaShareNetworkDiscoverer{}, nil
	case "share_server":
		return &discovery_services.ManillaShareServerDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
