package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/db/v1/datastores"
	"github.com/gophercloud/gophercloud/openstack/db/v1/instances"
)

func parseTroveTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func fetchTroveList(client *gophercloud.ServiceClient, path, listKey string, out interface{}) error {
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
		return nil
	}
	return json.Unmarshal(itemBytes, out)
}

// TroveBackup is a Trove backup resource.
type TroveBackup struct {
	ID        string
	Name      string
	Status    string
	InstanceID string
	ProjectID string
	Created   time.Time
	Updated   time.Time
}

// TroveCluster is a Trove instance cluster (when API available).
type TroveCluster struct {
	ID        string
	Name      string
	Status    string
	ProjectID string
	Created   time.Time
	Updated   time.Time
}

type TroveInstanceDiscoverer struct{}

func (d *TroveInstanceDiscoverer) ResourceType() string { return "instance" }

func (d *TroveInstanceDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := instances.List(client).AllPages()
		if err != nil {
			return
		}
		list, err := instances.ExtractInstances(pages)
		if err != nil {
			return
		}
		for _, inst := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "trove",
				ResourceType: "instance",
				ResourceID:   inst.ID,
				Resource:     inst,
			}:
			}
		}
	}()
	return ch, nil
}

type TroveBackupDiscoverer struct{}

func (d *TroveBackupDiscoverer) ResourceType() string { return "backup" }

func (d *TroveBackupDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		var wire []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			InstanceID string `json:"instance_id"`
			TenantID   string `json:"tenant_id"`
			Created    string `json:"created"`
			Updated    string `json:"updated"`
		}
		if err := fetchTroveList(client, "backups", "backups", &wire); err != nil {
			return
		}
		for _, b := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "trove",
				ResourceType: "backup",
				ResourceID:   b.ID,
				ProjectID:    b.TenantID,
				Resource: TroveBackup{
					ID:         b.ID,
					Name:       b.Name,
					Status:     b.Status,
					InstanceID: b.InstanceID,
					ProjectID:  b.TenantID,
					Created:    parseTroveTime(b.Created),
					Updated:    parseTroveTime(b.Updated),
				},
			}:
			}
		}
	}()
	return ch, nil
}

type TroveClusterDiscoverer struct{}

func (d *TroveClusterDiscoverer) ResourceType() string { return "cluster" }

func (d *TroveClusterDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		var wire []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Status   string `json:"status"`
			TenantID string `json:"tenant_id"`
			Created  string `json:"created"`
			Updated  string `json:"updated"`
		}
		if err := fetchTroveList(client, "clusters", "clusters", &wire); err != nil {
			return
		}
		for _, c := range wire {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "trove",
				ResourceType: "cluster",
				ResourceID:   c.ID,
				ProjectID:    c.TenantID,
				Resource: TroveCluster{
					ID:        c.ID,
					Name:      c.Name,
					Status:    c.Status,
					ProjectID: c.TenantID,
					Created:   parseTroveTime(c.Created),
					Updated:   parseTroveTime(c.Updated),
				},
			}:
			}
		}
	}()
	return ch, nil
}

type TroveDatastoreDiscoverer struct{}

func (d *TroveDatastoreDiscoverer) ResourceType() string { return "datastore" }

func (d *TroveDatastoreDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		pages, err := datastores.List(client).AllPages()
		if err != nil {
			return
		}
		list, err := datastores.ExtractDatastores(pages)
		if err != nil {
			return
		}
		for _, ds := range list {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "trove",
				ResourceType: "datastore",
				ResourceID:   ds.Name,
				Resource:     ds,
			}:
			}
		}
	}()
	return ch, nil
}
