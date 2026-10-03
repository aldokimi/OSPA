package services
import (
	"fmt"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	zaqaraudit "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/zaqar"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)
type ZaqarService struct{}
func init() {
	rootservices.MustRegister(&ZaqarService{})
	rootservices.RegisterResource("zaqar", "queue")
	rootservices.RegisterResource("zaqar", "message")
	rootservices.RegisterResource("zaqar", "subscription")
}
func (s *ZaqarService) Name() string { return "zaqar" }
func (s *ZaqarService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) { return session.GetZaqarClient() }
func (s *ZaqarService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "queue": return &zaqaraudit.QueueAuditor{}, nil
	case "message": return &zaqaraudit.MessageAuditor{}, nil
	case "subscription": return &zaqaraudit.SubscriptionAuditor{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
func (s *ZaqarService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "queue": return &discovery_services.ZaqarQueueDiscoverer{}, nil
	case "message": return &discovery_services.ZaqarMessageDiscoverer{}, nil
	case "subscription": return &discovery_services.ZaqarSubscriptionDiscoverer{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
