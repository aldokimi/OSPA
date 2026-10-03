package services

import (
	"fmt"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	senlinaudit "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/senlin"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

type SenlinService struct{}
func init() {
	rootservices.MustRegister(&SenlinService{})
	rootservices.RegisterResource("senlin", "cluster")
	rootservices.RegisterResource("senlin", "profile")
	rootservices.RegisterResource("senlin", "node")
	rootservices.RegisterResource("senlin", "policy")
}
func (s *SenlinService) Name() string { return "senlin" }
func (s *SenlinService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) { return session.GetSenlinClient() }
func (s *SenlinService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "cluster": return &senlinaudit.ClusterAuditor{}, nil
	case "profile": return &senlinaudit.ProfileAuditor{}, nil
	case "node": return &senlinaudit.NodeAuditor{}, nil
	case "policy": return &senlinaudit.PolicyAuditor{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
func (s *SenlinService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "cluster": return &discovery_services.SenlinClusterDiscoverer{}, nil
	case "profile": return &discovery_services.SenlinProfileDiscoverer{}, nil
	case "node": return &discovery_services.SenlinNodeDiscoverer{}, nil
	case "policy": return &discovery_services.SenlinPolicyDiscoverer{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
