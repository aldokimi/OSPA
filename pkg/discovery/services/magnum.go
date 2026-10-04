package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
)

// The Magnum API has no gophercloud package, so all Magnum discovery is done
// with raw requests through the service client. List responses use the
// resource name as the JSON key ({"clusters": [...]} etc.); clusters, bays
// and baymodels are identified by "uuid", templates by "id".

// parseMagnumTime parses the RFC-3339 timestamps Magnum returns. A zero time
// is returned when the field is missing or malformed.
func parseMagnumTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// MagnumCluster is a Magnum container cluster (v1).
type MagnumCluster struct {
	ID        string
	Name      string
	Status    string
	NodeCount int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MagnumClusterTemplate is a Magnum cluster template (v1).
type MagnumClusterTemplate struct {
	ID               string
	Name             string
	COE              string
	NetworkDriver    string
	TLSDisabled      bool
	InsecureRegistry *bool
	MasterLBEnabled  bool
	FloatingIPEnabled bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// MagnumBay is a Magnum bay (v1; bays are deprecated upstream).
type MagnumBay struct {
	ID        string
	Name      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MagnumBayModel is a Magnum bay model (v1; bay models are deprecated upstream).
type MagnumBayModel struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// fetchMagnumList issues GET {endpoint}/{path} and decodes the list payload
// keyed by listKey into out. Magnum returns the whole collection in a single
// response for these endpoints.
func fetchMagnumList(client *gophercloud.ServiceClient, path, listKey string, out interface{}) error {
	resp, err := client.Request("GET", client.ServiceURL(path), &gophercloud.RequestOpts{
		OkCodes: []int{http.StatusOK},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	itemBytes, ok := raw[listKey]
	if !ok {
		return nil // list key absent: treat as an empty collection
	}
	return json.Unmarshal(itemBytes, out)
}

// MagnumClusterDiscoverer discovers magnum/cluster resources.
type MagnumClusterDiscoverer struct{}

func (d *MagnumClusterDiscoverer) ResourceType() string {
	return "cluster"
}

func (d *MagnumClusterDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // the list endpoint is already scoped to the authenticated project

		var wire []struct {
			Uuid      string `json:"uuid"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			NodeCount int    `json:"node_count"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchMagnumList(client, "clusters", "clusters", &wire); err != nil {
			return
		}

		for _, c := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "magnum",
				ResourceType: "cluster",
				ResourceID:   c.Uuid,
				Resource: MagnumCluster{
					ID:        c.Uuid,
					Name:      c.Name,
					Status:    c.Status,
					NodeCount: c.NodeCount,
					CreatedAt: parseMagnumTime(c.CreatedAt),
					UpdatedAt: parseMagnumTime(c.UpdatedAt),
				},
			}:
			}
		}
	}()

	return ch, nil
}

// MagnumClusterTemplateDiscoverer discovers magnum/cluster_template resources.
type MagnumClusterTemplateDiscoverer struct{}

func (d *MagnumClusterTemplateDiscoverer) ResourceType() string {
	return "cluster_template"
}

func (d *MagnumClusterTemplateDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		var wire []struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			COE               string `json:"coe"`
			NetworkDriver     string `json:"network_driver"`
			TLSDisabled       bool   `json:"tls_disabled"`
			InsecureRegistry  *bool  `json:"insecure_registry"`
			MasterLBEnabled   bool   `json:"master_lb_enabled"`
			FloatingIPEnabled bool   `json:"floating_ip_enabled"`
			CreatedAt         string `json:"created_at"`
			UpdatedAt         string `json:"updated_at"`
		}
		if err := fetchMagnumList(client, "templates", "cluster_templates", &wire); err != nil {
			return
		}

		for _, t := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "magnum",
				ResourceType: "cluster_template",
				ResourceID:   t.ID,
				Resource: MagnumClusterTemplate{
					ID:                t.ID,
					Name:              t.Name,
					COE:               t.COE,
					NetworkDriver:     t.NetworkDriver,
					TLSDisabled:       t.TLSDisabled,
					InsecureRegistry:  t.InsecureRegistry,
					MasterLBEnabled:   t.MasterLBEnabled,
					FloatingIPEnabled: t.FloatingIPEnabled,
					CreatedAt:         parseMagnumTime(t.CreatedAt),
					UpdatedAt:         parseMagnumTime(t.UpdatedAt),
				},
			}:
			}
		}
	}()

	return ch, nil
}

// MagnumBayDiscoverer discovers magnum/bay resources.
type MagnumBayDiscoverer struct{}

func (d *MagnumBayDiscoverer) ResourceType() string {
	return "bay"
}

func (d *MagnumBayDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		var wire []struct {
			Uuid      string `json:"uuid"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchMagnumList(client, "bays", "bays", &wire); err != nil {
			return
		}

		for _, b := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "magnum",
				ResourceType: "bay",
				ResourceID:   b.Uuid,
				Resource: MagnumBay{
					ID:        b.Uuid,
					Name:      b.Name,
					Status:    b.Status,
					CreatedAt: parseMagnumTime(b.CreatedAt),
					UpdatedAt: parseMagnumTime(b.UpdatedAt),
				},
			}:
			}
		}
	}()

	return ch, nil
}

// MagnumBayModelDiscoverer discovers magnum/baymodel resources.
type MagnumBayModelDiscoverer struct{}

func (d *MagnumBayModelDiscoverer) ResourceType() string {
	return "baymodel"
}

func (d *MagnumBayModelDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		var wire []struct {
			Uuid      string `json:"uuid"`
			Name      string `json:"name"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchMagnumList(client, "baymodels", "baymodels", &wire); err != nil {
			return
		}

		for _, m := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "magnum",
				ResourceType: "baymodel",
				ResourceID:   m.Uuid,
				Resource: MagnumBayModel{
					ID:        m.Uuid,
					Name:      m.Name,
					CreatedAt: parseMagnumTime(m.CreatedAt),
					UpdatedAt: parseMagnumTime(m.UpdatedAt),
				},
			}:
			}
		}
	}()

	return ch, nil
}
