package dashboard

import (
	"sort"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/inventory"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/report"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/runstore"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
)

// CoverageRow shows how OSPA relates to one cluster resource type.
type CoverageRow struct {
	Service      string
	ResourceType string
	InCloud      int
	CloudError   string
	Reachable    bool
	InCatalog    bool
	InPolicy     bool
	PolicyRules  int
	LastFindings int
	Status       string // managed | unmanaged | absent | unreachable | no_catalog
	StatusLabel  string
	BarPct       int // relative to max InCloud for bar charts
}

// Bucket is a labeled count for breakdown charts.
type Bucket struct {
	Label string
	Count int
	Pct   int
}

// Stats is the dashboard view-model.
type Stats struct {
	Cloud              string
	Inventory          *inventory.Snapshot
	InventoryError     string
	PolicyPath         string
	PolicyRules        int
	PolicyComposites   int
	PolicyServices     int
	CatalogServices    int
	CatalogResources   int
	ManagedTypes       int
	UnmanagedInCloud   int
	UnmanagedCount     int // sum of resource instances not covered by policy
	AbsentManagedTypes int // in policy but 0 in cloud
	Coverage           []CoverageRow
	ByService          []Bucket
	BySeverity         []Bucket
	ByCategory         []Bucket
	InventoryBars      []Bucket
	LastRun            *runstore.Run
	LastRunFindings    int
	RemediableFindings int
	KPICoveragePct     int
	KPIViolationRate   int
}

// Build composes dashboard stats from inventory, policy, and run history.
func Build(cloud string, snap *inventory.Snapshot, invErr error, p *policy.Policy, policyPath string, runs []*runstore.Run) Stats {
	st := Stats{
		Cloud:           cloud,
		Inventory:       snap,
		PolicyPath:      policyPath,
		CatalogServices: len(services.List()),
	}
	if invErr != nil {
		st.InventoryError = invErr.Error()
	}

	supported := catalog.GetSupportedResources()
	for _, m := range supported {
		st.CatalogResources += len(m)
	}

	policyTypes := map[string]int{} // "service/resource" -> rule count
	if p != nil {
		st.PolicyRules = len(p.GetAllRules())
		st.PolicyComposites = len(p.GetAllCompositeRules())
		svcSet := map[string]bool{}
		for _, rule := range p.GetAllRules() {
			key := rule.Service + "/" + rule.Resource
			policyTypes[key]++
			svcSet[rule.Service] = true
		}
		for _, rule := range p.GetAllCompositeRules() {
			svcSet[rule.Service] = true
			for _, res := range rule.Resources {
				key := rule.Service + "/" + res
				if policyTypes[key] == 0 {
					policyTypes[key] = 0 // mark present via composite
				}
				policyTypes[key]++
			}
		}
		st.PolicyServices = len(svcSet)
	}

	cloudMap := map[string]inventory.ResourceCount{}
	maxCount := 1
	if snap != nil {
		for _, rc := range snap.Resources {
			cloudMap[rc.Service+"/"+rc.ResourceType] = rc
			if rc.Count > maxCount {
				maxCount = rc.Count
			}
		}
	}

	// Union of catalog + cloud + policy keys.
	keys := map[string]bool{}
	for svc, resMap := range supported {
		for res := range resMap {
			keys[svc+"/"+res] = true
		}
	}
	for k := range cloudMap {
		keys[k] = true
	}
	for k := range policyTypes {
		keys[k] = true
	}
	keyList := make([]string, 0, len(keys))
	for k := range keys {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)

	var last *runstore.Run
	for _, run := range runs {
		if run.Status == runstore.StatusCompleted {
			last = run
			break
		}
	}
	st.LastRun = last

	findingsByType := map[string]int{}
	sev := map[string]int{}
	cat := map[string]int{}
	svcFindings := map[string]int{}
	if last != nil {
		st.LastRunFindings = len(last.Findings)
		for _, f := range last.Findings {
			key := f.Service + "/" + f.ResourceType
			findingsByType[key]++
			severity := strings.ToLower(strings.TrimSpace(f.Severity))
			if severity == "" {
				severity = "unset"
			}
			sev[severity]++
			category := strings.ToLower(strings.TrimSpace(f.Category))
			if category == "" {
				category = "unset"
			}
			cat[category]++
			if f.Service != "" {
				svcFindings[f.Service]++
			}
			if isRemediable(f) {
				st.RemediableFindings++
			}
		}
		if last.Summary.Scanned > 0 {
			st.KPIViolationRate = (last.Summary.Violations * 100) / last.Summary.Scanned
		}
	}

	for _, key := range keyList {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 {
			continue
		}
		svc, res := parts[0], parts[1]
		row := CoverageRow{
			Service:      svc,
			ResourceType: res,
			InCatalog:    catalog.IsResourceSupported(svc, res),
			PolicyRules:  policyTypes[key],
			InPolicy:     policyTypes[key] > 0,
			LastFindings: findingsByType[key],
		}
		if rc, ok := cloudMap[key]; ok {
			row.InCloud = rc.Count
			row.CloudError = rc.Error
			row.Reachable = rc.Reachable
		}
		row.BarPct = (row.InCloud * 100) / maxCount
		row.Status, row.StatusLabel = classify(row)
		if row.Status == "managed" {
			st.ManagedTypes++
		}
		if row.Status == "unmanaged" {
			st.UnmanagedInCloud++
			st.UnmanagedCount += row.InCloud
		}
		if row.Status == "absent" {
			st.AbsentManagedTypes++
		}
		st.Coverage = append(st.Coverage, row)
	}

	coveredCloudTypes := 0
	cloudTypes := 0
	for _, row := range st.Coverage {
		if row.InCloud > 0 || (row.Reachable && row.CloudError == "") {
			if row.InCloud > 0 {
				cloudTypes++
				if row.InPolicy {
					coveredCloudTypes++
				}
			}
		}
	}
	if cloudTypes > 0 {
		st.KPICoveragePct = (coveredCloudTypes * 100) / cloudTypes
	}

	st.BySeverity = toBuckets(sev)
	st.ByCategory = toBuckets(cat)
	st.ByService = toBuckets(svcFindings)

	if snap != nil {
		invCounts := map[string]int{}
		for _, rc := range snap.Resources {
			if rc.Count <= 0 {
				continue
			}
			invCounts[rc.Service+"/"+rc.ResourceType] = rc.Count
		}
		st.InventoryBars = toBuckets(invCounts)
	}

	return st
}

func classify(row CoverageRow) (string, string) {
	if row.CloudError != "" && !row.Reachable {
		return "unreachable", "Service unreachable"
	}
	if !row.InCatalog {
		return "no_catalog", "Not in OSPA catalog"
	}
	if row.InPolicy && row.InCloud > 0 {
		return "managed", "Managed by policy"
	}
	if row.InPolicy && row.InCloud == 0 {
		return "absent", "In policy, none in cloud"
	}
	if !row.InPolicy && row.InCloud > 0 {
		return "unmanaged", "In cloud, no policy"
	}
	if row.CloudError != "" {
		return "unreachable", "Discovery error"
	}
	return "absent", "Not present"
}

func isRemediable(f report.Finding) bool {
	action := strings.ToLower(strings.TrimSpace(f.Action))
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(f.RecommendedAction))
	}
	return action != "" && action != "log"
}

func toBuckets(m map[string]int) []Bucket {
	if len(m) == 0 {
		return nil
	}
	total := 0
	keys := make([]string, 0, len(m))
	for k, v := range m {
		keys = append(keys, k)
		total += v
	}
	sort.Strings(keys)
	out := make([]Bucket, 0, len(keys))
	for _, k := range keys {
		pct := 0
		if total > 0 {
			pct = (m[k] * 100) / total
		}
		out = append(out, Bucket{Label: k, Count: m[k], Pct: pct})
	}
	// sort by count desc
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	return out
}
