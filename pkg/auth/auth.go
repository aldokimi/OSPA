package auth

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/utils/openstack/clientconfig"
)

// Session holds the authenticated provider client and configuration options.
type Session struct {
	Provider  *gophercloud.ProviderClient
	CloudName string
	Region    string
	// Opts, when set, is used for all service client creation (remote/explicit auth).
	// When nil, clients are created from clouds.yaml via CloudName.
	Opts *clientconfig.ClientOpts
}

// NewSession creates a new OpenStack session based on a cloud name found in clouds.yaml.
// If cloudName is empty, it looks for OS_CLOUD env var or standard env vars.
func NewSession(cloudName string) (*Session, error) {
	opts := &clientconfig.ClientOpts{
		Cloud: cloudName,
	}

	provider, err := clientconfig.AuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return &Session{
		Provider:  provider,
		CloudName: cloudName,
		Opts:      opts,
	}, nil
}

// AuthCredentials are explicit Keystone credentials for a remote cloud.
type AuthCredentials struct {
	AuthURL           string
	Username          string
	Password          string
	ProjectName       string
	ProjectID         string
	UserDomainName    string
	ProjectDomainName string
	RegionName        string
}

// NewSessionFromCredentials authenticates with explicit credentials (no clouds.yaml).
func NewSessionFromCredentials(displayName string, creds AuthCredentials) (*Session, error) {
	if creds.AuthURL == "" {
		return nil, fmt.Errorf("auth_url is required")
	}
	if creds.Username == "" && creds.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}
	userDomain := creds.UserDomainName
	if userDomain == "" {
		userDomain = "Default"
	}
	projectDomain := creds.ProjectDomainName
	if projectDomain == "" {
		projectDomain = userDomain
	}

	authInfo := &clientconfig.AuthInfo{
		AuthURL:           creds.AuthURL,
		Username:          creds.Username,
		Password:          creds.Password,
		ProjectName:       creds.ProjectName,
		ProjectID:         creds.ProjectID,
		UserDomainName:    userDomain,
		ProjectDomainName: projectDomain,
	}
	opts := &clientconfig.ClientOpts{
		AuthInfo:   authInfo,
		AuthType:   clientconfig.AuthPassword,
		RegionName: creds.RegionName,
	}

	provider, err := clientconfig.AuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	name := displayName
	if name == "" {
		name = creds.AuthURL
	}
	return &Session{
		Provider:  provider,
		CloudName: name,
		Region:    creds.RegionName,
		Opts:      opts,
	}, nil
}

func (s *Session) clientOpts() *clientconfig.ClientOpts {
	if s.Opts != nil {
		cp := *s.Opts
		return &cp
	}
	return &clientconfig.ClientOpts{Cloud: s.CloudName}
}

func (s *Session) newServiceClient(serviceType string) (*gophercloud.ServiceClient, error) {
	return clientconfig.NewServiceClient(serviceType, s.clientOpts())
}

// GetComputeClient returns a client for Nova (Compute)
func (s *Session) GetComputeClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("compute")
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %w", err)
	}
	return client, nil
}

// GetNetworkClient returns a client for Neutron (Network)
func (s *Session) GetNetworkClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("network")
	if err != nil {
		return nil, fmt.Errorf("failed to create network client: %w", err)
	}
	return client, nil
}

// GetBlockStorageClient returns a client for Cinder (Block Storage)
func (s *Session) GetBlockStorageClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("volumev3")
	if err != nil {
		return nil, fmt.Errorf("failed to create block storage client: %w", err)
	}
	return client, nil
}

// GetNeutronClient returns a client for Neutron
func (s *Session) GetNeutronClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("network")
	if err != nil {
		return nil, fmt.Errorf("failed to create neutron client: %w", err)
	}
	return client, nil
}

// GetCinderClient returns a client for Cinder
func (s *Session) GetCinderClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("volumev3")
	if err != nil {
		return nil, fmt.Errorf("failed to create cinder client: %w", err)
	}
	return client, nil
}

// GetNovaClient returns a client for Nova
func (s *Session) GetNovaClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("compute")
	if err != nil {
		return nil, fmt.Errorf("failed to create nova client: %w", err)
	}
	return client, nil
}

// GetKeystoneClient returns a client for Keystone (Identity)
func (s *Session) GetKeystoneClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("identity")
	if err != nil {
		return nil, fmt.Errorf("failed to create keystone client: %w", err)
	}
	return client, nil
}

// GetGlanceClient returns a client for Glance (Image)
func (s *Session) GetGlanceClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("image")
	if err != nil {
		return nil, fmt.Errorf("failed to create glance client: %w", err)
	}
	return client, nil
}

// GetDesignateClient returns a client for Designate (DNS)
func (s *Session) GetDesignateClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("dns")
	if err != nil {
		return nil, fmt.Errorf("failed to create designate client: %w", err)
	}
	return client, nil
}

// GetBarbicanClient returns a client for Barbican (Key Manager)
func (s *Session) GetBarbicanClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("key-manager")
	if err != nil {
		return nil, fmt.Errorf("failed to create barbican client: %w", err)
	}
	return client, nil
}

// GetSwiftClient returns a client for Swift (Object Store)
func (s *Session) GetSwiftClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("object-store")
	if err != nil {
		return nil, fmt.Errorf("failed to create swift client: %w", err)
	}
	return client, nil
}

// GetIronicClient returns a client for Ironic (Bare Metal)
func (s *Session) GetIronicClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("baremetal")
	if err != nil {
		return nil, fmt.Errorf("failed to create ironic client: %w", err)
	}
	return client, nil
}

// GetManilaClient returns a client for Manila (Shared File Systems).
func (s *Session) GetManilaClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("shared-file-systems")
	if err != nil {
		return nil, fmt.Errorf("failed to create manila client: %w", err)
	}
	return client, nil
}

// GetOctaviaClient returns a client for Octavia (Load Balancing).
func (s *Session) GetOctaviaClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("load-balancer")
	if err != nil {
		return nil, fmt.Errorf("failed to create octavia client: %w", err)
	}
	return client, nil
}

// GetSenlinClient returns a client for Senlin (Clustering).
func (s *Session) GetSenlinClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("clustering")
	if err != nil {
		return nil, fmt.Errorf("failed to create senlin client: %w", err)
	}
	return client, nil
}

// GetTroveClient returns a client for Trove (Database).
func (s *Session) GetTroveClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("database")
	if err != nil {
		return nil, fmt.Errorf("failed to create trove client: %w", err)
	}
	return client, nil
}

// GetZaqarClient returns a client for Zaqar (Messaging).
func (s *Session) GetZaqarClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("messaging")
	if err != nil {
		return nil, fmt.Errorf("failed to create zaqar client: %w", err)
	}
	return client, nil
}

// GetMagnumClient returns a client for Magnum.
func (s *Session) GetMagnumClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("container-infra")
	if err != nil {
		return nil, fmt.Errorf("failed to create magnum client: %w", err)
	}
	return client, nil
}

// GetHeatClient returns a client for Heat.
func (s *Session) GetHeatClient() (*gophercloud.ServiceClient, error) {
	client, err := s.newServiceClient("orchestration")
	if err != nil {
		return nil, fmt.Errorf("failed to create heat client: %w", err)
	}
	return client, nil
}
