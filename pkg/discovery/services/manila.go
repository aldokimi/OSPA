package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
)

func parseManilaTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func fetchManilaList(client *gophercloud.ServiceClient, path, listKey string, out interface{}) error {
	resp, err := client.Request("GET", client.ServiceURL(path), &gophercloud.RequestOpts{
		OkCodes: []int{http.StatusOK},
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	itemBytes, ok := raw[listKey]
	if !ok {
		return nil
	}
	return json.Unmarshal(itemBytes, out)
}

// ManilaShare is a Manila share resource (v2).
type ManilaShare struct {
	ID        string
	Name      string
	Status    string
	IsPublic  bool
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ManilaShareSnapshot is a Manila share snapshot (v2).
type ManilaShareSnapshot struct {
	ID        string
	Name      string
	Status    string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ManilaShareNetwork is a Manila share network (v2).
type ManilaShareNetwork struct {
	ID        string
	Name      string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ManilaShareServer is a Manila share server (v2).
type ManilaShareServer struct {
	ID        string
	Status    string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ManillaShareDiscoverer struct{}

func (d *ManillaShareDiscoverer) ResourceType() string { return "share" }

func (d *ManillaShareDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		path := "shares/detail"
		if allTenants {
			path = "shares/detail?all_tenants=1"
		}
		var wire []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			IsPublic  bool   `json:"is_public"`
			ProjectID string `json:"project_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchManilaList(client, path, "shares", &wire); err != nil {
			return
		}
		for _, s := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "manila",
				ResourceType: "share",
				ResourceID:   s.ID,
				ProjectID:    s.ProjectID,
				Resource: ManilaShare{
					ID:        s.ID,
					Name:      s.Name,
					Status:    s.Status,
					IsPublic:  s.IsPublic,
					ProjectID: s.ProjectID,
					CreatedAt: parseManilaTime(s.CreatedAt),
					UpdatedAt: parseManilaTime(s.UpdatedAt),
				},
			}:
			}
		}
	}()
	return ch, nil
}

type ManillaShareSnapshotDiscoverer struct{}

func (d *ManillaShareSnapshotDiscoverer) ResourceType() string { return "share_snapshot" }

func (d *ManillaShareSnapshotDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		path := "snapshots/detail"
		if allTenants {
			path = "snapshots/detail?all_tenants=1"
		}
		var wire []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			ProjectID string `json:"project_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchManilaList(client, path, "snapshots", &wire); err != nil {
			return
		}
		for _, s := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "manila",
				ResourceType: "share_snapshot",
				ResourceID:   s.ID,
				ProjectID:    s.ProjectID,
				Resource: ManilaShareSnapshot{
					ID:        s.ID,
					Name:      s.Name,
					Status:    s.Status,
					ProjectID: s.ProjectID,
					CreatedAt: parseManilaTime(s.CreatedAt),
					UpdatedAt: parseManilaTime(s.UpdatedAt),
				},
			}:
			}
		}
	}()
	return ch, nil
}

type ManillaShareNetworkDiscoverer struct{}

func (d *ManillaShareNetworkDiscoverer) ResourceType() string { return "share_network" }

func (d *ManillaShareNetworkDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		path := "share-networks/detail"
		if allTenants {
			path = "share-networks/detail?all_tenants=1"
		}
		var wire []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			ProjectID string `json:"project_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchManilaList(client, path, "share_networks", &wire); err != nil {
			return
		}
		for _, n := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "manila",
				ResourceType: "share_network",
				ResourceID:   n.ID,
				ProjectID:    n.ProjectID,
				Resource: ManilaShareNetwork{
					ID:        n.ID,
					Name:      n.Name,
					ProjectID: n.ProjectID,
					CreatedAt: parseManilaTime(n.CreatedAt),
					UpdatedAt: parseManilaTime(n.UpdatedAt),
				},
			}:
			}
		}
	}()
	return ch, nil
}

type ManillaShareServerDiscoverer struct{}

func (d *ManillaShareServerDiscoverer) ResourceType() string { return "share_server" }

func (d *ManillaShareServerDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		path := "share-servers/detail"
		if allTenants {
			path = "share-servers/detail?all_tenants=1"
		}
		var wire []struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ProjectID string `json:"project_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := fetchManilaList(client, path, "share_servers", &wire); err != nil {
			return
		}
		for _, s := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "manila",
				ResourceType: "share_server",
				ResourceID:   s.ID,
				ProjectID:    s.ProjectID,
				Resource: ManilaShareServer{
					ID:        s.ID,
					Status:    s.Status,
					ProjectID: s.ProjectID,
					CreatedAt: parseManilaTime(s.CreatedAt),
					UpdatedAt: parseManilaTime(s.UpdatedAt),
				},
			}:
			}
		}
	}()
	return ch, nil
}
