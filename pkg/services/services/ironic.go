package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/ironic"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// IronicService implements the Service interface for OpenStack Ironic.
//
// Supported resources:
//   - node: Bare metal nodes
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - port: Node ports (no status field)
//     Checks: age_gt, exempt_names
//     Actions: log, delete, tag
//   - driver: Drivers (read-only; no delete API)
//     Checks: exempt_names
//     Actions: log
//   - chassis: Chassis (legacy/optional; no gophercloud package, uses raw REST)
//     Checks: age_gt, exempt_names
//     Actions: log, delete, tag
type IronicService struct{}

func init() {
	rootservices.MustRegister(&IronicService{})
	rootservices.RegisterResource("ironic", "node")
	rootservices.RegisterResource("ironic", "port")
	rootservices.RegisterResource("ironic", "driver")
	rootservices.RegisterResource("ironic", "chassis")
}

func (s *IronicService) Name() string {
	return "ironic"
}

func (s *IronicService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetIronicClient()
}

func (s *IronicService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "node":
		return &ironic.NodeAuditor{}, nil
	case "port":
		return &ironic.PortAuditor{}, nil
	case "driver":
		return &ironic.DriverAuditor{}, nil
	case "chassis":
		return &ironic.ChassisAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *IronicService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "node":
		return &discovery_services.IronicNodeDiscoverer{}, nil
	case "port":
		return &discovery_services.IronicPortDiscoverer{}, nil
	case "driver":
		return &discovery_services.IronicDriverDiscoverer{}, nil
	case "chassis":
		return &discovery_services.IronicChassisDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
