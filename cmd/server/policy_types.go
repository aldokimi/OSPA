package main

import (
	"net/http"
	"sort"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/catalog"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
)

// policyType is one selectable service/resource policy target.
type policyType struct {
	Service   string
	Resource  string
	Checks    []string
	Fields    []policy.CheckFieldMeta
	RuleCount int
	Selected  bool
}

type serviceNav struct {
	Name      string
	Count     int
	Expanded  bool
	Resources []policyType
}

func (s *server) buildPolicyNav(selectedService, selectedResource string) []serviceNav {
	counts := map[string]int{}
	for _, rule := range s.ensureDraft().GetAllRules() {
		counts[rule.Service+"/"+rule.Resource]++
	}

	svcNames := services.List()
	sort.Strings(svcNames)
	supported := catalog.GetSupportedResources()
	nav := make([]serviceNav, 0, len(svcNames))

	for _, svcName := range svcNames {
		resMap := supported[svcName]
		resNames := make([]string, 0, len(resMap))
		for r := range resMap {
			resNames = append(resNames, r)
		}
		sort.Strings(resNames)

		svc, err := services.Get(svcName)
		entry := serviceNav{
			Name:     svcName,
			Expanded: selectedService == "" || selectedService == svcName,
		}
		for _, res := range resNames {
			pt := policyType{
				Service:   svcName,
				Resource:  res,
				RuleCount: counts[svcName+"/"+res],
				Selected:  selectedService == svcName && selectedResource == res,
			}
			if err == nil {
				if auditor, aerr := svc.GetResourceAuditor(res); aerr == nil {
					pt.Checks = append([]string(nil), auditor.ImplementedChecks()...)
					sort.Strings(pt.Checks)
					pt.Fields = policy.CheckFieldsFor(pt.Checks)
				}
			}
			entry.Count += pt.RuleCount
			entry.Resources = append(entry.Resources, pt)
		}
		nav = append(nav, entry)
	}
	return nav
}

func (s *server) selectedPolicyType(service, resource string) *policyType {
	if service == "" || resource == "" {
		return nil
	}
	nav := s.buildPolicyNav(service, resource)
	for _, svc := range nav {
		if svc.Name != service {
			continue
		}
		for i := range svc.Resources {
			if svc.Resources[i].Resource == resource {
				pt := svc.Resources[i]
				return &pt
			}
		}
	}
	return nil
}

func (s *server) filteredRuleCards(service, resource string) []ruleCard {
	cards := s.ruleCards()
	if service == "" {
		return cards
	}
	out := make([]ruleCard, 0, len(cards))
	for _, c := range cards {
		if !strings.EqualFold(c.Service, service) {
			continue
		}
		if resource != "" && !strings.EqualFold(c.Resource, resource) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func selectionFromRequest(r *http.Request) (service, resource string) {
	service = strings.TrimSpace(r.FormValue("service"))
	resource = strings.TrimSpace(r.FormValue("resource"))
	if service == "" {
		service = strings.TrimSpace(r.URL.Query().Get("service"))
	}
	if resource == "" {
		resource = strings.TrimSpace(r.URL.Query().Get("resource"))
	}
	// Prefer explicit nav selection when adding (form also posts service/resource).
	if sel := strings.TrimSpace(r.FormValue("nav_service")); sel != "" {
		service = sel
	}
	if sel := strings.TrimSpace(r.FormValue("nav_resource")); sel != "" {
		resource = sel
	}
	return service, resource
}

func (s *server) studioData(service, resource string) map[string]any {
	data := s.policyPageData()
	data["NavServices"] = s.buildPolicyNav(service, resource)
	data["SelectedService"] = service
	data["SelectedResource"] = resource
	data["SelectedType"] = s.selectedPolicyType(service, resource)
	// Always keep the full card list visible; selection only customizes the add form.
	data["Rules"] = s.ruleCards()
	matching := s.filteredRuleCards(service, resource)
	data["MatchingRules"] = matching
	data["MatchingCount"] = len(matching)
	data["FilterActive"] = service != ""
	return data
}

func (s *server) handlePolicyWorkspace(w http.ResponseWriter, r *http.Request) {
	s.ensureDraft()
	service, resource := selectionFromRequest(r)
	// Return the full studio shell so the left nav selection state updates with HTMX.
	s.render(w, "policy_studio_shell", s.studioData(service, resource))
}
