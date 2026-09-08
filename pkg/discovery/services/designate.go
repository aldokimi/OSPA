package services

import (
	"context"
	"fmt"
	"time"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
)

// Record represents a single DNS record value within a recordset.
//
// Designate has no standalone "record" API — a RecordSet holds a list of
// record values (e.g. multiple A records under one name). This type
// decomposes each recordset's Records slice into individually auditable
// entries.
type Record struct {
	ZoneID      string
	RecordSetID string
	Name        string
	Type        string
	TTL         int
	Status      string
	Value       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DesignateZoneDiscoverer discovers designate/zone resources.
type DesignateZoneDiscoverer struct{}

func (d *DesignateZoneDiscoverer) ResourceType() string {
	return "zone"
}

func (d *DesignateZoneDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // designate scopes zones by the authenticated project; no all-projects list flag in gophercloud's ListOpts

		pages, err := zones.List(client, zones.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		zoneList, err := zones.ExtractZones(pages)
		if err != nil {
			return
		}

		for _, z := range zoneList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "designate",
				ResourceType: "zone",
				ResourceID:   z.ID,
				ProjectID:    z.ProjectID,
				Resource:     z,
			}:
			}
		}
	}()

	return ch, nil
}

// DesignateRecordsetDiscoverer discovers designate/recordset resources.
//
// Recordsets are scoped per-zone, so discovery lists zones first and then
// lists each zone's recordsets.
type DesignateRecordsetDiscoverer struct{}

func (d *DesignateRecordsetDiscoverer) ResourceType() string {
	return "recordset"
}

func (d *DesignateRecordsetDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		zonePages, err := zones.List(client, zones.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		zoneList, err := zones.ExtractZones(zonePages)
		if err != nil {
			return
		}

		for _, z := range zoneList {
			if ctx.Err() != nil {
				return
			}

			rsPages, err := recordsets.ListByZone(client, z.ID, recordsets.ListOpts{}).AllPages()
			if err != nil {
				continue
			}

			rsList, err := recordsets.ExtractRecordSets(rsPages)
			if err != nil {
				continue
			}

			for _, rs := range rsList {
				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "designate",
					ResourceType: "recordset",
					ResourceID:   rs.ID,
					ProjectID:    rs.ProjectID,
					Resource:     rs,
				}:
				}
			}
		}
	}()

	return ch, nil
}

// DesignateRecordDiscoverer discovers designate/record resources.
//
// Each recordset's Records slice is decomposed into individual Record
// entries, one per value.
type DesignateRecordDiscoverer struct{}

func (d *DesignateRecordDiscoverer) ResourceType() string {
	return "record"
}

func (d *DesignateRecordDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		zonePages, err := zones.List(client, zones.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		zoneList, err := zones.ExtractZones(zonePages)
		if err != nil {
			return
		}

		for _, z := range zoneList {
			if ctx.Err() != nil {
				return
			}

			rsPages, err := recordsets.ListByZone(client, z.ID, recordsets.ListOpts{}).AllPages()
			if err != nil {
				continue
			}

			rsList, err := recordsets.ExtractRecordSets(rsPages)
			if err != nil {
				continue
			}

			for _, rs := range rsList {
				for i, value := range rs.Records {
					rec := Record{
						ZoneID:      rs.ZoneID,
						RecordSetID: rs.ID,
						Name:        rs.Name,
						Type:        rs.Type,
						TTL:         rs.TTL,
						Status:      rs.Status,
						Value:       value,
						CreatedAt:   rs.CreatedAt,
						UpdatedAt:   rs.UpdatedAt,
					}

					select {
					case <-ctx.Done():
						return
					case ch <- discovery.Job{
						Service:      "designate",
						ResourceType: "record",
						ResourceID:   fmt.Sprintf("%s/%d", rs.ID, i),
						ProjectID:    rs.ProjectID,
						Resource:     rec,
					}:
					}
				}
			}
		}
	}()

	return ch, nil
}
