package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/octavia"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

type OctaviaService struct{}
func init() {
	rootservices.MustRegister(&OctaviaService{})
	rootservices.RegisterResource("octavia", "loadbalancer")
	rootservices.RegisterResource("octavia", "listener")
	rootservices.RegisterResource("octavia", "pool")
	rootservices.RegisterResource("octavia", "member")
	rootservices.RegisterResource("octavia", "healthmonitor")
}
func (s *OctaviaService) Name() string { return "octavia" }
func (s *OctaviaService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) { return session.GetOctaviaClient() }
func (s *OctaviaService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "loadbalancer": return &octavia.LoadBalancerAuditor{}, nil
	case "listener": return &octavia.ListenerAuditor{}, nil
	case "pool": return &octavia.PoolAuditor{}, nil
	case "member": return &octavia.MemberAuditor{}, nil
	case "healthmonitor": return &octavia.HealthMonitorAuditor{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
func (s *OctaviaService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "loadbalancer": return &discovery_services.OctaviaLoadBalancerDiscoverer{}, nil
	case "listener": return &discovery_services.OctaviaListenerDiscoverer{}, nil
	case "pool": return &discovery_services.OctaviaPoolDiscoverer{}, nil
	case "member": return &discovery_services.OctaviaMemberDiscoverer{}, nil
	case "healthmonitor": return &discovery_services.OctaviaHealthMonitorDiscoverer{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
