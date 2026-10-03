package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/magnum"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// MagnumService implements the Service interface for OpenStack Magnum.
//
// Supported resources:
//   - cluster: Container clusters
//     Checks: status, age_gt, exempt_names
//     Actions: log, delete
//   - cluster_template: Cluster templates
//     Checks: age_gt, exempt_names
//     Actions: log, delete
//   - bay: Bays (deprecated)
//     Checks: status, age_gt, exempt_names
//     Actions: log, delete
//   - baymodel: Bay models (deprecated)
//     Checks: age_gt, exempt_names
//     Actions: log, delete
//
// Magnum has no gophercloud package: discovery and deletion use raw HTTP
// requests (GET /clusters, /templates, /bays, /baymodels; DELETE
// /{resource}/{id}).
type MagnumService struct{}

func init() {
	rootservices.MustRegister(&MagnumService{})
	rootservices.RegisterResource("magnum", "cluster")
	rootservices.RegisterResource("magnum", "cluster_template")
	rootservices.RegisterResource("magnum", "bay")
	rootservices.RegisterResource("magnum", "baymodel")
}

func (s *MagnumService) Name() string {
	return "magnum"
}

func (s *MagnumService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetMagnumClient()
}

func (s *MagnumService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "cluster":
		return &magnum.ClusterAuditor{}, nil
	case "cluster_template":
		return &magnum.ClusterTemplateAuditor{}, nil
	case "bay":
		return &magnum.BayAuditor{}, nil
	case "baymodel":
		return &magnum.BaymodelAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *MagnumService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "cluster":
		return &discovery_services.MagnumClusterDiscoverer{}, nil
	case "cluster_template":
		return &discovery_services.MagnumClusterTemplateDiscoverer{}, nil
	case "bay":
		return &discovery_services.MagnumBayDiscoverer{}, nil
	case "baymodel":
		return &discovery_services.MagnumBaymodelDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
