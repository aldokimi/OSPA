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
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func fetchTroveList(client *gophercloud.ServiceClient, path, listKey string, out interface{}) error {
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

// TroveBackup is a database backup (Trove has no gophercloud backups package).
type TroveBackup struct {
	ID         string
	Name       string
	Status     string
	InstanceID string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TroveCluster is a Trove cluster resource.
type TroveCluster struct {
	ID        string
	Name      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TroveInstanceDiscoverer discovers trove/instance resources.
type TroveInstanceDiscoverer struct{}

func (d *TroveInstanceDiscoverer) ResourceType() string { return "instance" }

func (d *TroveInstanceDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
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

// TroveBackupDiscoverer discovers trove/backup resources via raw API.
type TroveBackupDiscoverer struct{}

func (d *TroveBackupDiscoverer) ResourceType() string { return "backup" }

func (d *TroveBackupDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		var wire []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			InstanceID string `json:"instance_id"`
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
				Resource: TroveBackup{
					ID:         b.ID,
					Name:       b.Name,
					Status:     b.Status,
					InstanceID: b.InstanceID,
					CreatedAt:  parseTroveTime(b.Created),
					UpdatedAt:  parseTroveTime(b.Updated),
				},
			}:
			}
		}
	}()
	return ch, nil
}

// TroveClusterDiscoverer discovers trove/cluster resources via raw API.
type TroveClusterDiscoverer struct{}

func (d *TroveClusterDiscoverer) ResourceType() string { return "cluster" }

func (d *TroveClusterDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
	ch := make(chan discovery.Job)
	go func() {
		defer close(ch)
		var rawList []map[string]interface{}
		if err := fetchTroveList(client, "clusters", "clusters", &rawList); err != nil {
			return
		}
		for _, m := range rawList {
			id, _ := m["id"].(string)
			name, _ := m["name"].(string)
			status, _ := m["status"].(string)
			if status == "" {
				if task, ok := m["task"].(map[string]interface{}); ok {
					status, _ = task["name"].(string)
				}
			}
			created, _ := m["created"].(string)
			updated, _ := m["updated"].(string)
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "trove",
				ResourceType: "cluster",
				ResourceID:   id,
				Resource: TroveCluster{
					ID:        id,
					Name:      name,
					Status:    status,
					CreatedAt: parseTroveTime(created),
					UpdatedAt: parseTroveTime(updated),
				},
			}:
			}
		}
	}()
	return ch, nil
}

// TroveDatastoreDiscoverer discovers trove/datastore resources.
type TroveDatastoreDiscoverer struct{}

func (d *TroveDatastoreDiscoverer) ResourceType() string { return "datastore" }

func (d *TroveDatastoreDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	_ = allTenants
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
				ResourceID:   ds.ID,
				Resource:     ds,
			}:
			}
		}
	}()
	return ch, nil
}
