package dashboard

import (
	"testing"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/inventory"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/report"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/runstore"
)

func TestBuild_ManagedAndUnmanaged(t *testing.T) {
	catalog.RegisterResource("neutron", "network")
	catalog.RegisterResource("neutron", "port")
	catalog.RegisterResource("nova", "instance")

	snap := &inventory.Snapshot{
		Cloud:   "devstack",
		Total:   15,
		TakenAt: time.Now().UTC(),
		Resources: []inventory.ResourceCount{
			{Service: "neutron", ResourceType: "network", Count: 5, Reachable: true},
			{Service: "neutron", ResourceType: "port", Count: 10, Reachable: true},
			{Service: "nova", ResourceType: "instance", Count: 0, Reachable: true},
		},
	}
	p := &policy.Policy{
		Policies: []policy.ServicePolicy{{
			Service: "neutron",
			Rules: []policy.Rule{{
				Name:     "unused-nets",
				Service:  "neutron",
				Resource: "network",
				Check:    policy.CheckConditions{Unused: true},
				Action:   "log",
			}},
		}},
	}
	store := runstore.New()
	run := store.Create("r1", "devstack", "pol.yaml", false, false)
	store.SetStatus(run.ID, runstore.StatusRunning, "")
	store.AppendFinding(run.ID, report.Finding{
		Service: "neutron", ResourceType: "network", Severity: "high", Category: "hygiene", Action: "delete",
	})
	store.SetSummary(run.ID, report.Summary{Scanned: 5, Violations: 1, Written: 1})
	store.SetStatus(run.ID, runstore.StatusCompleted, "")

	stats := Build("devstack", snap, nil, p, "pol.yaml", store.List())
	if stats.UnmanagedInCloud == 0 {
		t.Fatal("expected unmanaged port type")
	}
	if stats.ManagedTypes == 0 {
		t.Fatal("expected managed network type")
	}
	if stats.KPICoveragePct == 0 {
		t.Fatal("expected non-zero coverage")
	}
	if stats.LastRunFindings != 1 {
		t.Fatalf("findings = %d", stats.LastRunFindings)
	}
	if stats.RemediableFindings != 1 {
		t.Fatalf("remediable = %d", stats.RemediableFindings)
	}
	if len(stats.InventoryBars) != 2 {
		t.Fatalf("inventory bars = %d, want 2", len(stats.InventoryBars))
	}
}
