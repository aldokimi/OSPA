package services

import (
	"fmt"

	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/designate"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/gophercloud/gophercloud"
)

// DesignateService implements the Service interface for OpenStack Designate.
//
// Supported resources:
//   - zone: DNS zones
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - recordset: DNS recordsets
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - record: DNS records
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
type DesignateService struct{}

func init() {
	rootservices.MustRegister(&DesignateService{})
	rootservices.RegisterResource("designate", "zone")
	rootservices.RegisterResource("designate", "recordset")
	rootservices.RegisterResource("designate", "record")
}

func (s *DesignateService) Name() string {
	return "designate"
}

func (s *DesignateService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetDesignateClient()
}

func (s *DesignateService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "zone":
		return &designate.ZoneAuditor{}, nil
	case "recordset":
		return &designate.RecordsetAuditor{}, nil
	case "record":
		return &designate.RecordAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *DesignateService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "zone":
		return &discovery_services.DesignateZoneDiscoverer{}, nil
	case "recordset":
		return &discovery_services.DesignateRecordsetDiscoverer{}, nil
	case "record":
		return &discovery_services.DesignateRecordDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
