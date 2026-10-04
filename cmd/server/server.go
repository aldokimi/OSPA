package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/cloudprofile"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/report"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/runner"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/runstore"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
)

type server struct {
	templates     *template.Template
	static        fs.FS
	store         *runstore.Store
	profiles      *cloudprofile.Store
	defaultPolicy string
	mu            sync.Mutex
	cancels       map[string]context.CancelFunc
	invMu         sync.Mutex
	invCache      map[string]invCacheEntry
	draftMu       sync.Mutex
	draft         *policy.Policy
	draftPath     string
	connMu        sync.RWMutex
	conn          *liveConnection
}

type serviceView struct {
	Name      string
	Resources []string
}

func newServer(defaultPolicy string) (*server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("static fs: %w", err)
	}
	profiles, err := cloudprofile.Open(cloudprofile.DefaultPath())
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}
	return &server{
		templates:     tmpl,
		static:        staticRoot,
		store:         runstore.New(),
		profiles:      profiles,
		defaultPolicy: defaultPolicy,
		cancels:       make(map[string]context.CancelFunc),
		invCache:      map[string]invCacheEntry{},
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.static))))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("GET /dashboard/partial", s.handleDashboardPartial)
	mux.HandleFunc("GET /home", s.handleHome)
	mux.HandleFunc("GET /runs", s.handleRunsPage)
	mux.HandleFunc("POST /runs", s.handleStartRun)
	mux.HandleFunc("POST /runs/from-yaml", s.handleStartRunFromYAML)
	mux.HandleFunc("GET /runs/{id}", s.handleRunDetail)
	mux.HandleFunc("GET /runs/{id}/summary", s.handleRunSummary)
	mux.HandleFunc("GET /runs/{id}/findings", s.handleRunFindings)
	mux.HandleFunc("POST /runs/{id}/cancel", s.handleCancelRun)
	mux.HandleFunc("GET /policies", s.handlePoliciesPage)
	mux.HandleFunc("GET /policies/workspace", s.handlePolicyWorkspace)
	mux.HandleFunc("POST /policies/validate", s.handleValidatePolicy)
	mux.HandleFunc("POST /policies/load", s.handlePolicyLoad)
	mux.HandleFunc("POST /policies/sync-yaml", s.handlePolicySyncYAML)
	mux.HandleFunc("POST /policies/rules", s.handlePolicyAddRule)
	mux.HandleFunc("POST /policies/rules/{index}/delete", s.handlePolicyDeleteRule)
	mux.HandleFunc("POST /policies/save", s.handlePolicySave)
	mux.HandleFunc("GET /catalog", s.handleCatalog)
	mux.HandleFunc("GET /profiles", s.handleProfilesPage)
	mux.HandleFunc("POST /profiles/remote", s.handleProfileCreateRemote)
	mux.HandleFunc("POST /profiles/local", s.handleProfileCreateLocal)
	mux.HandleFunc("POST /profiles/{id}/connect", s.handleProfileConnect)
	mux.HandleFunc("POST /profiles/disconnect", s.handleProfileDisconnect)
	mux.HandleFunc("POST /profiles/{id}/delete", s.handleProfileDelete)
	return mux
}

func (s *server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	s.render(w, "home", map[string]any{
		"Title": "Home",
		"Nav":   "home",
		"Runs":  s.store.List(),
	})
}

func (s *server) handleRunsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":         "Runs",
		"Nav":           "runs",
		"DefaultPolicy": s.defaultPolicy,
		"Runs":          s.store.List(),
	}
	for k, v := range s.connectionBannerData() {
		data[k] = v
	}
	s.render(w, "runs", data)
}

func (s *server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	_ = r
	supported := catalog.GetSupportedResources()
	names := services.List()
	sort.Strings(names)
	views := make([]serviceView, 0, len(names))
	for _, name := range names {
		resources := make([]string, 0)
		if m, ok := supported[name]; ok {
			for res := range m {
				resources = append(resources, res)
			}
			sort.Strings(resources)
		}
		views = append(views, serviceView{Name: name, Resources: resources})
	}
	s.render(w, "catalog", map[string]any{
		"Title":    "Catalog",
		"Nav":      "catalog",
		"Services": views,
	})
}

func (s *server) handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		_ = r.ParseForm()
	}
	p, _, err := s.loadPolicyFromRequest(r)
	if err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	s.render(w, "validate_ok", map[string]any{
		"Rules":      len(p.GetAllRules()),
		"Composites": len(p.GetAllCompositeRules()),
	})
}

func (s *server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, cloudLabel, err := s.requireConnected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	policyPath := strings.TrimSpace(r.FormValue("policy_path"))
	if policyPath == "" {
		http.Error(w, "policy_path is required", http.StatusBadRequest)
		return
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := s.startRun(session, cloudLabel, policyPath, p, r.FormValue("apply") == "1", r.FormValue("all_tenants") == "1")
	http.Redirect(w, r, "/runs/"+id, http.StatusSeeOther)
}

func (s *server) handleStartRunFromYAML(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		_ = r.ParseForm()
	}
	session, cloudLabel, err := s.requireConnected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p, label, err := s.loadPolicyFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := s.startRun(session, cloudLabel, label, p, false, r.FormValue("all_tenants") == "1")
	http.Redirect(w, r, "/runs/"+id, http.StatusSeeOther)
}

func (s *server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	run, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, "run_detail", map[string]any{
		"Title": "Run",
		"Nav":   "runs",
		"Run":   run,
	})
}

func (s *server) handleRunSummary(w http.ResponseWriter, r *http.Request) {
	run, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, "summary", run)
}

func (s *server) handleRunFindings(w http.ResponseWriter, r *http.Request) {
	run, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, "findings_table", run.Findings)
}

func (s *server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	cancel, ok := s.cancels[id]
	s.mu.Unlock()
	if ok {
		cancel()
		s.store.SetStatus(id, runstore.StatusCancelled, "cancelled by user")
	}
	http.Redirect(w, r, "/runs/"+id, http.StatusSeeOther)
}

func (s *server) loadPolicyFromRequest(r *http.Request) (*policy.Policy, string, error) {
	source := r.FormValue("source")
	if source == "path" || (source == "" && r.FormValue("policy_path") != "" && r.FormValue("policy_yaml") == "") {
		path := strings.TrimSpace(r.FormValue("policy_path"))
		if path == "" {
			return nil, "", fmt.Errorf("policy_path is required")
		}
		p, err := policy.Load(path)
		return p, path, err
	}

	if file, hdr, err := r.FormFile("policy_file"); err == nil {
		defer func() { _ = file.Close() }()
		b, err := io.ReadAll(io.LimitReader(file, 4<<20))
		if err != nil {
			return nil, "", err
		}
		p, err := policy.LoadBytes(b)
		return p, "upload:" + filepath.Base(hdr.Filename), err
	}

	yamlBody := strings.TrimSpace(r.FormValue("policy_yaml"))
	if yamlBody == "" {
		return nil, "", fmt.Errorf("provide policy_path, policy_yaml, or policy_file")
	}
	p, err := policy.LoadBytes([]byte(yamlBody))
	return p, "paste", err
}

func (s *server) requireConnected() (*auth.Session, string, error) {
	c := s.activeConnection()
	if c == nil || c.Session == nil {
		return nil, "", fmt.Errorf("no cloud connected — open Profiles and connect first")
	}
	return c.Session, c.ProfileName, nil
}

func (s *server) startRun(session *auth.Session, cloudLabel, policyLabel string, p *policy.Policy, apply, allTenants bool) string {
	id := newRunID()
	s.store.Create(id, cloudLabel, policyLabel, apply, allTenants)

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[id] = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.cancels, id)
			s.mu.Unlock()
			cancel()
		}()

		s.store.SetStatus(id, runstore.StatusRunning, "")
		outcome, err := runner.Run(ctx, runner.Options{
			Cloud:      cloudLabel,
			Session:    session,
			Policy:     p,
			Apply:      apply,
			AllTenants: allTenants,
			OnFinding: func(f report.Finding) {
				s.store.AppendFinding(id, f)
			},
		})
		if err != nil {
			if ctx.Err() != nil {
				s.store.SetStatus(id, runstore.StatusCancelled, err.Error())
				return
			}
			s.store.SetStatus(id, runstore.StatusFailed, err.Error())
			return
		}
		s.store.SetSummary(id, outcome.Summary)
		s.store.SetStatus(id, runstore.StatusCompleted, "")
	}()

	return id
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
