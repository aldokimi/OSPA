package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/cloudprofile"
)

type liveConnection struct {
	ProfileID   string
	ProfileName string
	Source      cloudprofile.Source
	Session     *auth.Session
	ConnectedAt time.Time
}

func (s *server) activeConnection() *liveConnection {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	if s.conn == nil {
		return nil
	}
	cp := *s.conn
	return &cp
}

func (s *server) setConnection(c *liveConnection) {
	s.connMu.Lock()
	s.conn = c
	s.connMu.Unlock()
	s.invMu.Lock()
	s.invCache = map[string]invCacheEntry{}
	s.invMu.Unlock()
}

func (s *server) clearConnection() {
	s.setConnection(nil)
}

func (s *server) handleProfilesPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "connected":
		flash = "Connected."
	case "disconnected":
		flash = "Disconnected."
	case "saved":
		flash = "Profile saved."
	case "deleted":
		flash = "Profile deleted."
	}
	s.render(w, "profiles", s.profilesPageData(flash))
}

func (s *server) profilesPageData(flash string) map[string]any {
	localClouds, _ := listCloudNames()
	conn := s.activeConnection()
	activeID := ""
	connectedName := ""
	if conn != nil {
		activeID = conn.ProfileID
		connectedName = conn.ProfileName
	}
	return map[string]any{
		"Title":          "Profiles",
		"Nav":            "profiles",
		"Profiles":       s.profiles.List(),
		"LocalClouds":    localClouds,
		"ActiveID":       activeID,
		"ConnectedName":  connectedName,
		"Connected":      conn != nil,
		"Flash":          flash,
		"HasLocalClouds": len(localClouds) > 0,
	}
}

func (s *server) handleProfileCreateRemote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p := cloudprofile.Profile{
		Name:              strings.TrimSpace(r.FormValue("name")),
		Source:            cloudprofile.SourceRemote,
		AuthURL:           strings.TrimSpace(r.FormValue("auth_url")),
		Username:          strings.TrimSpace(r.FormValue("username")),
		Password:          r.FormValue("password"),
		ProjectName:       strings.TrimSpace(r.FormValue("project_name")),
		ProjectID:         strings.TrimSpace(r.FormValue("project_id")),
		UserDomainName:    strings.TrimSpace(r.FormValue("user_domain_name")),
		ProjectDomainName: strings.TrimSpace(r.FormValue("project_domain_name")),
		RegionName:        strings.TrimSpace(r.FormValue("region_name")),
	}
	if p.Name == "" {
		p.Name = p.AuthURL
	}
	saved, err := s.profiles.Upsert(p)
	if err != nil {
		s.render(w, "profiles", s.profilesPageData("Error: "+err.Error()))
		return
	}
	if r.FormValue("connect_now") == "1" {
		if err := s.connectProfile(saved.ID, true); err != nil {
			s.render(w, "profiles", s.profilesPageData("Saved, but connect failed: "+err.Error()))
			return
		}
		http.Redirect(w, r, "/profiles?ok=connected", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/profiles?ok=saved", http.StatusSeeOther)
}

func (s *server) handleProfileCreateLocal(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cloud := strings.TrimSpace(r.FormValue("local_cloud"))
	if cloud == "" {
		s.render(w, "profiles", s.profilesPageData("Error: choose a local cloud"))
		return
	}
	if r.FormValue("confirm_local") != "1" {
		s.render(w, "profiles", s.profilesPageData("Error: confirm permission to use the local clouds.yaml entry"))
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "local:" + cloud
	}
	saved, err := s.profiles.Upsert(cloudprofile.Profile{
		Name:       name,
		Source:     cloudprofile.SourceLocal,
		LocalCloud: cloud,
	})
	if err != nil {
		s.render(w, "profiles", s.profilesPageData("Error: "+err.Error()))
		return
	}
	if r.FormValue("connect_now") == "1" {
		if err := s.connectProfile(saved.ID, true); err != nil {
			s.render(w, "profiles", s.profilesPageData("Saved, but connect failed: "+err.Error()))
			return
		}
		http.Redirect(w, r, "/profiles?ok=connected", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/profiles?ok=saved", http.StatusSeeOther)
}

func (s *server) handleProfileConnect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = r.ParseForm()
	// Local profiles require explicit confirm each connect.
	p, ok := s.profiles.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if p.Source == cloudprofile.SourceLocal && r.FormValue("confirm_local") != "1" {
		s.render(w, "profiles", s.profilesPageData("Error: confirm permission before connecting to local cloud "+p.LocalCloud))
		return
	}
	if err := s.connectProfile(id, true); err != nil {
		s.render(w, "profiles", s.profilesPageData("Connect failed: "+err.Error()))
		return
	}
	http.Redirect(w, r, "/profiles?ok=connected", http.StatusSeeOther)
}

func (s *server) handleProfileDisconnect(w http.ResponseWriter, r *http.Request) {
	s.clearConnection()
	_ = s.profiles.SetActive("")
	http.Redirect(w, r, "/profiles?ok=disconnected", http.StatusSeeOther)
}

func (s *server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if c := s.activeConnection(); c != nil && c.ProfileID == id {
		s.clearConnection()
	}
	if err := s.profiles.Delete(id); err != nil {
		s.render(w, "profiles", s.profilesPageData("Error: "+err.Error()))
		return
	}
	http.Redirect(w, r, "/profiles?ok=deleted", http.StatusSeeOther)
}

func (s *server) connectProfile(id string, persistActive bool) error {
	p, ok := s.profiles.Get(id)
	if !ok {
		return fmt.Errorf("profile not found")
	}
	var (
		session *auth.Session
		err     error
	)
	switch p.Source {
	case cloudprofile.SourceLocal:
		session, err = auth.NewSession(p.LocalCloud)
	case cloudprofile.SourceRemote:
		session, err = auth.NewSessionFromCredentials(p.Name, auth.AuthCredentials{
			AuthURL:           p.AuthURL,
			Username:          p.Username,
			Password:          p.Password,
			ProjectName:       p.ProjectName,
			ProjectID:         p.ProjectID,
			UserDomainName:    p.UserDomainName,
			ProjectDomainName: p.ProjectDomainName,
			RegionName:        p.RegionName,
		})
	default:
		return fmt.Errorf("unknown profile source %q", p.Source)
	}
	if err != nil {
		return err
	}
	s.setConnection(&liveConnection{
		ProfileID:   p.ID,
		ProfileName: p.Name,
		Source:      p.Source,
		Session:     session,
		ConnectedAt: time.Now().UTC(),
	})
	if persistActive {
		_ = s.profiles.SetActive(p.ID)
	}
	return nil
}

// connectionBannerData is embedded in pages that need cloud status.
func (s *server) connectionBannerData() map[string]any {
	c := s.activeConnection()
	if c == nil {
		return map[string]any{
			"Connected": false,
		}
	}
	return map[string]any{
		"Connected":     true,
		"ConnectedName": c.ProfileName,
		"ConnectedAt":   c.ConnectedAt,
		"ConnectedSrc":  string(c.Source),
	}
}
