package services

import (
	"fmt"

	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/keystone"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/gophercloud/gophercloud"
)

// KeystoneService implements the Service interface for OpenStack Keystone.
//
// Supported resources:
//   - user: Users
//     Checks: status, age_gt, unused, exempt_names, password_expired, inactive_days, has_admin_role, mfa_enabled
//     Actions: log, delete, tag
//   - role: Roles
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - project: Projects
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - domain: Domains
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - group: Groups
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
//   - service: Services
//     Checks: status, age_gt, unused, exempt_names
//     Actions: log, delete, tag
type KeystoneService struct{}

func init() {
	rootservices.MustRegister(&KeystoneService{})
	rootservices.RegisterResource("keystone", "user")
	rootservices.RegisterResource("keystone", "role")
	rootservices.RegisterResource("keystone", "project")
	rootservices.RegisterResource("keystone", "domain")
	rootservices.RegisterResource("keystone", "group")
	rootservices.RegisterResource("keystone", "service")
}

func (s *KeystoneService) Name() string {
	return "keystone"
}

func (s *KeystoneService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) {
	return session.GetKeystoneClient()
}

func (s *KeystoneService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "user":
		return &keystone.UserAuditor{}, nil
	case "role":
		return &keystone.RoleAuditor{}, nil
	case "project":
		return &keystone.ProjectAuditor{}, nil
	case "domain":
		return &keystone.DomainAuditor{}, nil
	case "group":
		return &keystone.GroupAuditor{}, nil
	case "service":
		return &keystone.ServiceAuditor{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}

func (s *KeystoneService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "user":
		return &discovery_services.KeystoneUserDiscoverer{}, nil
	case "role":
		return &discovery_services.KeystoneRoleDiscoverer{}, nil
	case "project":
		return &discovery_services.KeystoneProjectDiscoverer{}, nil
	case "domain":
		return &discovery_services.KeystoneDomainDiscoverer{}, nil
	case "group":
		return &discovery_services.KeystoneGroupDiscoverer{}, nil
	case "service":
		return &discovery_services.KeystoneServiceDiscoverer{}, nil
	default:
		return nil, fmt.Errorf("unsupported resource type %q for service %q", resourceType, s.Name())
	}
}
