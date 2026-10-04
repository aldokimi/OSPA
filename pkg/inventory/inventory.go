package inventory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	"github.com/gophercloud/gophercloud"
)

// ResourceCount is one service/resource inventory cell.
type ResourceCount struct {
	Service      string `json:"service"`
	ResourceType string `json:"resource_type"`
	Count        int    `json:"count"`
	Error        string `json:"error,omitempty"`
	Reachable    bool   `json:"reachable"`
}

// Snapshot is a point-in-time view of cluster inventory.
type Snapshot struct {
	Cloud       string          `json:"cloud"`
	AllTenants  bool            `json:"all_tenants"`
	TakenAt     time.Time       `json:"taken_at"`
	DurationMS  int64           `json:"duration_ms"`
	Total       int             `json:"total"`
	ServicesOK  int             `json:"services_ok"`
	ServicesErr int             `json:"services_err"`
	Resources   []ResourceCount `json:"resources"`
}

// Options configures an inventory scan.
type Options struct {
	Cloud      string
	Session    *auth.Session // when set, used instead of Cloud/clouds.yaml
	AllTenants bool
	// Services limits the scan; empty means all registered services.
	Services []string
}

// Scan authenticates and counts resources for each registered discoverer.
func Scan(ctx context.Context, opts Options) (*Snapshot, error) {
	if opts.Session == nil && opts.Cloud == "" {
		return nil, fmt.Errorf("cloud or session is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()
	session := opts.Session
	if session == nil {
		var err error
		session, err = auth.NewSession(opts.Cloud)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}
	cloudLabel := opts.Cloud
	if cloudLabel == "" {
		cloudLabel = session.CloudName
	}

	serviceNames := opts.Services
	if len(serviceNames) == 0 {
		serviceNames = services.List()
	}
	sort.Strings(serviceNames)

	supported := catalog.GetSupportedResources()
	type workItem struct {
		service, resource string
	}
	var work []workItem
	for _, svc := range serviceNames {
		resources := make([]string, 0)
		if m, ok := supported[svc]; ok {
			for r := range m {
				resources = append(resources, r)
			}
		}
		sort.Strings(resources)
		for _, r := range resources {
			work = append(work, workItem{svc, r})
		}
	}

	out := make([]ResourceCount, len(work))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	var clientMu sync.Mutex
	clients := map[string]*gophercloud.ServiceClient{}
	clientErrs := map[string]error{}

	getClient := func(name string, svc services.Service) (*gophercloud.ServiceClient, error) {
		clientMu.Lock()
		defer clientMu.Unlock()
		if c, ok := clients[name]; ok {
			return c, nil
		}
		if err, ok := clientErrs[name]; ok {
			return nil, err
		}
		c, err := svc.GetClient(session)
		if err != nil {
			clientErrs[name] = err
			return nil, err
		}
		clients[name] = c
		return c, nil
	}

	for i, item := range work {
		wg.Add(1)
		go func(i int, item workItem) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				out[i] = ResourceCount{Service: item.service, ResourceType: item.resource, Error: ctx.Err().Error()}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			rc := ResourceCount{Service: item.service, ResourceType: item.resource}
			svc, err := services.Get(item.service)
			if err != nil {
				rc.Error = err.Error()
				out[i] = rc
				return
			}
			client, err := getClient(item.service, svc)
			if err != nil {
				rc.Error = err.Error()
				out[i] = rc
				return
			}
			rc.Reachable = true

			disc, err := svc.GetResourceDiscoverer(item.resource)
			if err != nil {
				rc.Error = err.Error()
				out[i] = rc
				return
			}
			jobs, err := disc.Discover(ctx, client, opts.AllTenants)
			if err != nil {
				rc.Error = err.Error()
				out[i] = rc
				return
			}
			count := 0
			for range jobs {
				count++
				if ctx.Err() != nil {
					break
				}
			}
			rc.Count = count
			out[i] = rc
		}(i, item)
	}
	wg.Wait()

	snap := &Snapshot{
		Cloud:      cloudLabel,
		AllTenants: opts.AllTenants,
		TakenAt:    start.UTC(),
		DurationMS: time.Since(start).Milliseconds(),
		Resources:  out,
	}
	seenOK := map[string]bool{}
	seenErr := map[string]bool{}
	for _, rc := range out {
		snap.Total += rc.Count
		if rc.Error != "" && !rc.Reachable {
			seenErr[rc.Service] = true
		} else if rc.Reachable && rc.Error == "" {
			seenOK[rc.Service] = true
		} else if rc.Reachable {
			seenOK[rc.Service] = true
		}
	}
	for svc := range seenOK {
		snap.ServicesOK++
		delete(seenErr, svc)
	}
	snap.ServicesErr = len(seenErr)
	return snap, nil
}
