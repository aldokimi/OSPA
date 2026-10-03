package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/heat"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// HeatService implements the Service interface for OpenStack Heat.
//
// Supported resources:
//   - stack: Stacks
//     Checks: status, age_gt, exempt_names
//     Actions: log, delete
//   - resource: Stack resources
//     Checks: status, age_gt, exempt_names
//     Actions: log
//   - template: Templates
//     Checks: exempt_names
//     Actions: log
//   - snapshot: Stack snapshots
//     Checks: age_gt, exempt_names
//     Actions: log
type HeatService struct{}

func init() {
	rootservices.MustRegister(&HeatService{})
	rootservices.RegisterResource("heat", "stack")
	rootservices.RegisterResource("heat", "resource")
	rootservices.RegisterResource("heat", "template")
	rootservices.RegisterResource("heat", "snapshot")
}

func (s *HeatService) Name() string {
	return "heat"
}

func (s *HeatService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetHeatClient()
}

func (s *HeatService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "stack":
		return &heat.StackAuditor{}, nil
	case "resource":
		return &heat.ResourceAuditor{}, nil
	case "template":
		return &heat.TemplateAuditor{}, nil
	case "snapshot":
		return &heat.SnapshotAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *HeatService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "stack":
		return &discovery_services.HeatStackDiscoverer{}, nil
	case "resource":
		return &discovery_services.HeatResourceDiscoverer{}, nil
	case "template":
		return &discovery_services.HeatTemplateDiscoverer{}, nil
	case "snapshot":
		return &discovery_services.HeatSnapshotDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
