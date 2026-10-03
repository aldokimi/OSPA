package services
import (
	"fmt"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	trovedaudit "github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/trove"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discovery_services "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	rootservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)
type TroveService struct{}
func init() {
	rootservices.MustRegister(&TroveService{})
	rootservices.RegisterResource("trove", "instance")
	rootservices.RegisterResource("trove", "cluster")
	rootservices.RegisterResource("trove", "backup")
	rootservices.RegisterResource("trove", "datastore")
}
func (s *TroveService) Name() string { return "trove" }
func (s *TroveService) GetClient(session *auth.Session) (*gophercloud.ServiceClient, error) { return session.GetTroveClient() }
func (s *TroveService) GetResourceAuditor(resourceType string) (audit.Auditor, error) {
	switch resourceType {
	case "instance": return &trovedaudit.InstanceAuditor{}, nil
	case "cluster": return &trovedaudit.ClusterAuditor{}, nil
	case "backup": return &trovedaudit.BackupAuditor{}, nil
	case "datastore": return &trovedaudit.DatastoreAuditor{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
func (s *TroveService) GetResourceDiscoverer(resourceType string) (discovery.Discoverer, error) {
	switch resourceType {
	case "instance": return &discovery_services.TroveInstanceDiscoverer{}, nil
	case "cluster": return &discovery_services.TroveClusterDiscoverer{}, nil
	case "backup": return &discovery_services.TroveBackupDiscoverer{}, nil
	case "datastore": return &discovery_services.TroveDatastoreDiscoverer{}, nil
	default: return nil, fmt.Errorf("unsupported resource type %q", resourceType)
	}
}
