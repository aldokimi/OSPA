package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stackresources"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacks"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacktemplates"
)

// HeatResourceInStack carries the parent stack name alongside a
// stackresources.Resource, since the heat resource listing is scoped to one
// stack and the Resource struct alone doesn't carry that association.
type HeatResourceInStack struct {
	stackresources.Resource
	StackName string
}

// HeatTemplate identifies a stack's template. Templates have no lifecycle of
// their own; they are addressed by their owning stack.
type HeatTemplate struct {
	StackName string
	StackID   string
}

// HeatSnapshot is a single entry of a stack's snapshot list, as returned by
// the raw Heat API (gophercloud has no snapshots package).
type HeatSnapshot struct {
	StackName    string
	SnapshotTime time.Time
	Description  string
}

// listStacks is a small helper shared by the per-stack discoverers below.
func listStacks(client *gophercloud.ServiceClient) ([]stacks.ListedStack, error) {
	pages, err := stacks.List(client, stacks.ListOpts{}).AllPages()
	if err != nil {
		return nil, err
	}
	return stacks.ExtractStacks(pages)
}

// HeatStackDiscoverer discovers heat/stack resources.
type HeatStackDiscoverer struct{}

func (d *HeatStackDiscoverer) ResourceType() string {
	return "stack"
}

func (d *HeatStackDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // stacks are already scoped to the authenticated project

		stackList, err := listStacks(client)
		if err != nil {
			return
		}

		for _, s := range stackList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "heat",
				ResourceType: "stack",
				ResourceID:   s.ID,
				Resource:     s,
			}:
			}
		}
	}()

	return ch, nil
}

// HeatResourceDiscoverer discovers heat/resource resources.
//
// Resources are scoped per-stack, so discovery lists stacks first and then
// lists each stack's resources.
type HeatResourceDiscoverer struct{}

func (d *HeatResourceDiscoverer) ResourceType() string {
	return "resource"
}

func (d *HeatResourceDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		stackList, err := listStacks(client)
		if err != nil {
			return
		}

		for _, s := range stackList {
			if ctx.Err() != nil {
				return
			}

			pages, err := stackresources.List(client, s.Name, s.ID, stackresources.ListOpts{}).AllPages()
			if err != nil {
				continue
			}

			resourceList, err := stackresources.ExtractResources(pages)
			if err != nil {
				continue
			}

			for _, r := range resourceList {
				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "heat",
					ResourceType: "resource",
					ResourceID:   s.Name + "/" + r.Name,
					Resource:     HeatResourceInStack{Resource: r, StackName: s.Name},
				}:
				}
			}
		}
	}()

	return ch, nil
}

// HeatTemplateDiscoverer discovers heat/template resources.
//
// A template is the read-only definition of its stack, so discovery fetches
// each stack's template (GET /stacks/{stack}/template) and emits one job per
// stack whose template is reachable.
type HeatTemplateDiscoverer struct{}

func (d *HeatTemplateDiscoverer) ResourceType() string {
	return "template"
}

func (d *HeatTemplateDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		stackList, err := listStacks(client)
		if err != nil {
			return
		}

		for _, s := range stackList {
			if ctx.Err() != nil {
				return
			}

			if _, err := stacktemplates.Get(client, s.Name, s.ID).Extract(); err != nil {
				// Template is not readable (e.g. stack being deleted); skip it.
				continue
			}

			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "heat",
				ResourceType: "template",
				ResourceID:   s.ID,
				Resource:     HeatTemplate{StackName: s.Name, StackID: s.ID},
			}:
			}
		}
	}()

	return ch, nil
}

// HeatSnapshotDiscoverer discovers heat/snapshot resources.
//
// The Heat snapshots API (GET /stacks/{stack}/snapshots) has no gophercloud
// package, so discovery issues the raw request through the service client.
type HeatSnapshotDiscoverer struct{}

func (d *HeatSnapshotDiscoverer) ResourceType() string {
	return "snapshot"
}

func (d *HeatSnapshotDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		stackList, err := listStacks(client)
		if err != nil {
			return
		}

		for _, s := range stackList {
			if ctx.Err() != nil {
				return
			}

			resp, err := client.Request("GET", client.ServiceURL("stacks", s.Name, "snapshots"), &gophercloud.RequestOpts{
				OkCodes: []int{http.StatusOK},
			})
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			var parsed struct {
				Snapshots []struct {
					SnapshotTime string `json:"snapshot_time"`
					Description  string `json:"description"`
				} `json:"snapshots"`
			}
			dec := json.NewDecoder(resp.Body)
			if err := dec.Decode(&parsed); err != nil {
				continue
			}

			for _, snap := range parsed.Snapshots {
				snapshot := HeatSnapshot{StackName: s.Name, Description: snap.Description}
				if ts, perr := time.Parse(time.RFC3339, snap.SnapshotTime); perr == nil {
					snapshot.SnapshotTime = ts
				}

				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "heat",
					ResourceType: "snapshot",
					ResourceID:   s.Name + "@" + snap.SnapshotTime,
					Resource:     snapshot,
				}:
				}
			}
		}
	}()

	return ch, nil
}
