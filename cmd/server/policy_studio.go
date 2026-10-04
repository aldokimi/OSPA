package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
)

type ruleCard struct {
	Index       int
	Service     string
	Name        string
	Description string
	Resource    string
	Action      string
	Severity    string
	Category    string
	GuideRef    string
	Checks      []policy.CheckSummary
}

type compositeCard struct {
	Index       int
	Service     string
	Name        string
	Description string
	Resources   string
	Action      string
	Severity    string
	Category    string
	Pattern     string
}

func (s *server) ensureDraft() *policy.Policy {
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	if s.draft != nil {
		return s.draft
	}
	if p, err := policy.Load(s.defaultPolicy); err == nil {
		s.draft = p
		s.draftPath = s.defaultPolicy
		return s.draft
	}
	s.draft = &policy.Policy{Version: "v1"}
	return s.draft
}

func (s *server) setDraft(p *policy.Policy, path string) {
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	s.draft = p
	if path != "" {
		s.draftPath = path
	}
}

func (s *server) draftPathOrDefault() string {
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	if s.draftPath != "" {
		return s.draftPath
	}
	return s.defaultPolicy
}

func (s *server) draftYAML() string {
	p := s.ensureDraft()
	b, err := policy.MarshalYAML(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *server) ruleCards() []ruleCard {
	p := s.ensureDraft()
	rules := p.GetAllRules()
	cards := make([]ruleCard, 0, len(rules))
	for i, rule := range rules {
		cards = append(cards, ruleCard{
			Index:       i,
			Service:     rule.Service,
			Name:        rule.Name,
			Description: rule.Description,
			Resource:    rule.Resource,
			Action:      rule.Action,
			Severity:    rule.Severity,
			Category:    rule.Category,
			GuideRef:    rule.GuideRef,
			Checks:      policy.SummarizeChecks(rule.Check),
		})
	}
	return cards
}

func (s *server) compositeCards() []compositeCard {
	p := s.ensureDraft()
	rules := p.GetAllCompositeRules()
	cards := make([]compositeCard, 0, len(rules))
	for i, rule := range rules {
		pattern := ""
		if rule.Check != nil {
			if v, ok := rule.Check["pattern"].(string); ok {
				pattern = v
			}
		}
		cards = append(cards, compositeCard{
			Index:       i,
			Service:     rule.Service,
			Name:        rule.Name,
			Description: rule.Description,
			Resources:   strings.Join(rule.Resources, ", "),
			Action:      rule.Action,
			Severity:    rule.Severity,
			Category:    rule.Category,
			Pattern:     pattern,
		})
	}
	return cards
}

func catalogOptions() (servicesList []string, resourcesByService map[string][]string) {
	servicesList = services.List()
	sort.Strings(servicesList)
	resourcesByService = map[string][]string{}
	supported := catalog.GetSupportedResources()
	for _, svc := range servicesList {
		res := make([]string, 0)
		if m, ok := supported[svc]; ok {
			for r := range m {
				res = append(res, r)
			}
			sort.Strings(res)
		}
		resourcesByService[svc] = res
	}
	return servicesList, resourcesByService
}

func (s *server) policyPageData() map[string]any {
	svcList, resMap := catalogOptions()
	resJSON, _ := json.Marshal(resMap)
	data := map[string]any{
		"Title":         "Policies",
		"Nav":           "policies",
		"DefaultPolicy": s.defaultPolicy,
		"DraftPath":     s.draftPathOrDefault(),
		"SampleYAML":    s.draftYAML(),
		"Rules":         s.ruleCards(),
		"Composites":    s.compositeCards(),
		"Services":      svcList,
		"ResourcesJSON": template.JS(resJSON),
		"Resources":     resMap,
	}
	for k, v := range s.connectionBannerData() {
		data[k] = v
	}
	return data
}

func (s *server) handlePoliciesPage(w http.ResponseWriter, r *http.Request) {
	s.ensureDraft()
	service, resource := selectionFromRequest(r)
	s.render(w, "policies", s.studioData(service, resource))
}

func (s *server) handlePolicyLoad(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(r.FormValue("policy_path"))
	if path == "" {
		http.Error(w, "policy_path is required", http.StatusBadRequest)
		return
	}
	p, err := policy.Load(path)
	if err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	s.setDraft(p, path)
	service, resource := selectionFromRequest(r)
	s.render(w, "policy_studio_update", s.studioData(service, resource))
}

func (s *server) handlePolicySyncYAML(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	yamlBody := strings.TrimSpace(r.FormValue("policy_yaml"))
	if yamlBody == "" {
		s.render(w, "validate_err", "YAML is empty")
		return
	}
	p, err := policy.LoadBytes([]byte(yamlBody))
	if err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	s.setDraft(p, "paste")
	service, resource := selectionFromRequest(r)
	s.render(w, "policy_studio_update", s.studioData(service, resource))
}

func (s *server) handlePolicyAddRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule, err := ruleFromForm(r)
	if err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}

	s.ensureDraft()
	s.draftMu.Lock()
	p := s.draft
	inserted := false
	for i := range p.Policies {
		if p.Policies[i].Service == rule.Service {
			p.Policies[i].Rules = append(p.Policies[i].Rules, rule)
			inserted = true
			break
		}
	}
	if !inserted {
		p.Policies = append(p.Policies, policy.ServicePolicy{
			Service: rule.Service,
			Rules:   []policy.Rule{rule},
		})
	}
	s.draft = p
	s.draftMu.Unlock()

	if b, err := policy.MarshalYAML(p); err == nil {
		if _, err := policy.LoadBytes(b); err != nil {
			// Roll forward visually but surface validation error in the OOB target.
			w.Header().Set("HX-Retarget", "#validate-result")
			s.render(w, "validate_err", err.Error())
			return
		}
	}
	s.render(w, "policy_studio_update", s.studioData(rule.Service, rule.Resource))
}

func (s *server) handlePolicyDeleteRule(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || idx < 0 {
		http.Error(w, "bad index", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	service, resource := selectionFromRequest(r)

	s.draftMu.Lock()
	p := s.draft
	if p == nil {
		s.draftMu.Unlock()
		http.NotFound(w, r)
		return
	}
	remaining := 0
	deleted := false
	for si := range p.Policies {
		n := len(p.Policies[si].Rules)
		if idx < remaining+n {
			local := idx - remaining
			if service == "" {
				service = p.Policies[si].Service
				resource = p.Policies[si].Rules[local].Resource
			}
			p.Policies[si].Rules = append(p.Policies[si].Rules[:local], p.Policies[si].Rules[local+1:]...)
			deleted = true
			break
		}
		remaining += n
	}
	if deleted {
		cleaned := p.Policies[:0]
		for _, sp := range p.Policies {
			if len(sp.Rules) > 0 {
				cleaned = append(cleaned, sp)
			}
		}
		p.Policies = cleaned
		s.draft = p
	}
	s.draftMu.Unlock()

	if !deleted {
		http.NotFound(w, r)
		return
	}
	s.render(w, "policy_studio_update", s.studioData(service, resource))
}

func (s *server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(r.FormValue("policy_path"))
	if path == "" {
		path = s.defaultPolicy
	}
	p := s.ensureDraft()
	b, err := policy.MarshalYAML(p)
	if err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	if _, err := policy.LoadBytes(b); err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		s.render(w, "validate_err", err.Error())
		return
	}
	s.setDraft(p, path)
	s.render(w, "validate_ok", map[string]any{
		"Rules":      len(p.GetAllRules()),
		"Composites": len(p.GetAllCompositeRules()),
	})
}

func ruleFromForm(r *http.Request) (policy.Rule, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	service := strings.TrimSpace(r.FormValue("service"))
	resource := strings.TrimSpace(r.FormValue("resource"))
	action := strings.TrimSpace(r.FormValue("action"))
	if name == "" || service == "" || resource == "" || action == "" {
		return policy.Rule{}, fmt.Errorf("name, service, resource, and action are required")
	}
	rule := policy.Rule{
		Name:        name,
		Description: strings.TrimSpace(r.FormValue("description")),
		Service:     service,
		Resource:    resource,
		Action:      action,
		Severity:    strings.TrimSpace(r.FormValue("severity")),
		Category:    strings.TrimSpace(r.FormValue("category")),
		GuideRef:    strings.TrimSpace(r.FormValue("guide_ref")),
	}

	allowed := []string{}
	if svc, err := services.Get(service); err == nil {
		if auditor, err := svc.GetResourceAuditor(resource); err == nil {
			allowed = auditor.ImplementedChecks()
		}
	}
	check, err := checksFromForm(r, allowed)
	if err != nil {
		return policy.Rule{}, err
	}
	if len(check.UsedChecks()) == 0 {
		return policy.Rule{}, fmt.Errorf("add at least one check condition")
	}
	rule.Check = check
	return rule, nil
}

func checksFromForm(r *http.Request, allowed []string) (policy.CheckConditions, error) {
	var check policy.CheckConditions
	if len(allowed) == 0 {
		// Fall back to any posted check_* keys we know about.
		allowed = []string{
			"status", "age_gt", "unused", "exempt_names", "direction", "ethertype",
			"protocol", "port", "remote_ip_prefix", "port_range_wide", "unassociated",
			"shared_network", "no_security_group", "visibility", "is_public",
			"secret_type", "record_type", "tls_ciphers", "has_tls_container",
		}
	}
	for _, name := range allowed {
		key := "check_" + name
		meta := policy.CheckField(name)
		raw := strings.TrimSpace(r.FormValue(key))
		switch meta.Kind {
		case policy.CheckFieldBool:
			if r.FormValue(key) == "1" {
				if err := setCheckBool(&check, name, true); err != nil {
					return check, err
				}
			}
		case policy.CheckFieldBoolOpt:
			if raw == "" {
				continue
			}
			v := raw == "true"
			if err := setCheckBoolPtr(&check, name, &v); err != nil {
				return check, err
			}
		case policy.CheckFieldInt:
			if raw == "" {
				continue
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				return check, fmt.Errorf("%s: %w", name, err)
			}
			if err := setCheckInt(&check, name, n); err != nil {
				return check, err
			}
		case policy.CheckFieldList:
			if raw == "" {
				continue
			}
			var parts []string
			for _, p := range strings.Split(raw, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					parts = append(parts, p)
				}
			}
			if err := setCheckList(&check, name, parts); err != nil {
				return check, err
			}
		default:
			if raw == "" {
				continue
			}
			if err := setCheckString(&check, name, raw); err != nil {
				return check, err
			}
		}
	}
	return check, nil
}

func setCheckBool(c *policy.CheckConditions, name string, v bool) error {
	switch name {
	case "unused":
		c.Unused = v
	case "unassociated":
		c.Unassociated = v
	case "port_range_wide":
		c.PortRangeWide = v
	case "shared_network":
		c.SharedNetwork = v
	case "no_security_group":
		c.NoSecurityGroup = v
	case "no_keypair":
		c.NoKeypair = v
	case "password_expired":
		c.PasswordExpired = v
	case "has_admin_role":
		c.HasAdminRole = v
	case "admin_via_group":
		c.AdminViaGroup = v
	default:
		return fmt.Errorf("unsupported bool check %q", name)
	}
	return nil
}

func setCheckBoolPtr(c *policy.CheckConditions, name string, v *bool) error {
	switch name {
	case "is_public":
		c.IsPublic = v
	case "encrypted":
		c.Encrypted = v
	case "attached":
		c.Attached = v
	case "has_backup":
		c.HasBackup = v
	case "quota_set":
		c.QuotaSet = v
	case "public_write":
		c.PublicWrite = v
	case "mfa_enabled":
		c.MFAEnabled = v
	case "tls_disabled":
		c.TlsDisabled = v
	case "console_enabled":
		c.ConsoleEnabled = v
	case "has_tls_container":
		c.HasTlsContainer = v
	default:
		return fmt.Errorf("unsupported bool_opt check %q", name)
	}
	return nil
}

func setCheckInt(c *policy.CheckConditions, name string, v int) error {
	switch name {
	case "port":
		c.Port = v
	default:
		return fmt.Errorf("unsupported int check %q", name)
	}
	return nil
}

func setCheckList(c *policy.CheckConditions, name string, v []string) error {
	switch name {
	case "exempt_names":
		c.ExemptNames = v
	case "image_name":
		c.ImageName = v
	case "qos_spec_keys":
		c.QosSpecKeys = v
	default:
		return fmt.Errorf("unsupported list check %q", name)
	}
	return nil
}

func setCheckString(c *policy.CheckConditions, name, v string) error {
	switch name {
	case "status":
		c.Status = v
	case "age_gt":
		c.AgeGT = v
	case "direction":
		c.Direction = v
	case "ethertype":
		c.Ethertype = v
	case "protocol":
		c.Protocol = v
	case "remote_ip_prefix":
		c.RemoteIPPrefix = v
	case "visibility":
		c.Visibility = v
	case "secret_type":
		c.SecretType = v
	case "secret_risk":
		c.SecretRisk = v
	case "record_type":
		c.RecordType = v
	case "tls_ciphers":
		c.TlsCiphers = v
	case "network_driver":
		c.NetworkDriver = v
	case "boot_interface":
		c.BootInterface = v
	case "qos_consumer":
		c.QosConsumer = v
	case "token_provider":
		c.TokenProvider = v
	default:
		return fmt.Errorf("unsupported string check %q", name)
	}
	return nil
}
