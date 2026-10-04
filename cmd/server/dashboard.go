package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/dashboard"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/inventory"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

var errNoCloud = errors.New("no cloud connected — open Profiles and connect first")

type invCacheEntry struct {
	snap    *inventory.Snapshot
	err     error
	expires time.Time
}

func (s *server) getInventory(session *auth.Session, allTenants bool, refresh bool) (*inventory.Snapshot, error) {
	key := session.CloudName
	if allTenants {
		key += "|all"
	}

	s.invMu.Lock()
	if s.invCache == nil {
		s.invCache = map[string]invCacheEntry{}
	}
	if !refresh {
		if ent, ok := s.invCache[key]; ok && time.Now().Before(ent.expires) {
			s.invMu.Unlock()
			return ent.snap, ent.err
		}
	}
	s.invMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	snap, err := inventory.Scan(ctx, inventory.Options{
		Session:    session,
		Cloud:      session.CloudName,
		AllTenants: allTenants,
	})

	s.invMu.Lock()
	s.invCache[key] = invCacheEntry{snap: snap, err: err, expires: time.Now().Add(60 * time.Second)}
	s.invMu.Unlock()
	return snap, err
}

func (s *server) buildDashboard(r *http.Request) dashboard.Stats {
	policyPath := strings.TrimSpace(r.URL.Query().Get("policy"))
	if policyPath == "" {
		policyPath = s.defaultPolicy
	}
	allTenants := r.URL.Query().Get("all_tenants") == "1"
	refresh := r.URL.Query().Get("refresh") == "1"

	var p *policy.Policy
	if policyPath != "" {
		if loaded, err := policy.Load(policyPath); err == nil {
			p = loaded
		}
	}

	conn := s.activeConnection()
	cloud := ""
	var snap *inventory.Snapshot
	var invErr error
	if conn == nil || conn.Session == nil {
		invErr = errNoCloud
	} else {
		cloud = conn.ProfileName
		snap, invErr = s.getInventory(conn.Session, allTenants, refresh)
	}

	return dashboard.Build(cloud, snap, invErr, p, policyPath, s.store.List())
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats := s.buildDashboard(r)
	data := map[string]any{
		"Title":         "Dashboard",
		"Nav":           "dashboard",
		"DefaultPolicy": s.defaultPolicy,
		"Cloud":         stats.Cloud,
		"PolicyPath":    stats.PolicyPath,
		"AllTenants":    r.URL.Query().Get("all_tenants") == "1",
		"Stats":         stats,
	}
	for k, v := range s.connectionBannerData() {
		data[k] = v
	}
	s.render(w, "dashboard", data)
}

func (s *server) handleDashboardPartial(w http.ResponseWriter, r *http.Request) {
	stats := s.buildDashboard(r)
	data := map[string]any{
		"DefaultPolicy": s.defaultPolicy,
		"Cloud":         stats.Cloud,
		"PolicyPath":    stats.PolicyPath,
		"AllTenants":    r.URL.Query().Get("all_tenants") == "1",
		"Stats":         stats,
	}
	for k, v := range s.connectionBannerData() {
		data[k] = v
	}
	s.render(w, "dashboard_body", data)
}
