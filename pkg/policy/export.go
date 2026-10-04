package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

// CheckSummary is a human-readable check condition for UI chips.
type CheckSummary struct {
	Key   string
	Value string
}

// SummarizeChecks returns non-empty check fields as key/value pairs.
func SummarizeChecks(c CheckConditions) []CheckSummary {
	names := c.UsedChecks()
	out := make([]CheckSummary, 0, len(names))
	for _, name := range names {
		out = append(out, CheckSummary{Key: name, Value: checkValueString(c, name)})
	}
	return out
}

func checkValueString(c CheckConditions, name string) string {
	switch name {
	case "status":
		return c.Status
	case "age_gt":
		return c.AgeGT
	case "unused":
		return "true"
	case "exempt_names":
		return strings.Join(c.ExemptNames, ", ")
	case "direction":
		return c.Direction
	case "ethertype":
		return c.Ethertype
	case "protocol":
		return c.Protocol
	case "port":
		return fmt.Sprintf("%d", c.Port)
	case "remote_ip_prefix":
		return c.RemoteIPPrefix
	case "port_range_wide":
		return "true"
	case "unassociated":
		return "true"
	case "shared_network":
		return "true"
	case "no_security_group":
		return "true"
	case "image_name":
		return strings.Join(c.ImageName, ", ")
	case "no_keypair":
		return "true"
	case "is_public":
		if c.IsPublic == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.IsPublic)
	case "encrypted":
		if c.Encrypted == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.Encrypted)
	case "attached":
		if c.Attached == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.Attached)
	case "has_backup":
		if c.HasBackup == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.HasBackup)
	case "qos_consumer":
		return c.QosConsumer
	case "qos_spec_keys":
		return strings.Join(c.QosSpecKeys, ", ")
	case "visibility":
		return c.Visibility
	case "password_expired":
		return "true"
	case "mfa_enabled":
		if c.MFAEnabled == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.MFAEnabled)
	case "has_admin_role":
		return "true"
	case "admin_via_group":
		return "true"
	case "token_provider":
		return c.TokenProvider
	case "quota_set":
		if c.QuotaSet == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.QuotaSet)
	case "public_write":
		if c.PublicWrite == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.PublicWrite)
	case "secret_type":
		return c.SecretType
	case "secret_risk":
		return c.SecretRisk
	case "record_type":
		return c.RecordType
	case "tls_disabled":
		if c.TlsDisabled == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.TlsDisabled)
	case "network_driver":
		return c.NetworkDriver
	case "console_enabled":
		if c.ConsoleEnabled == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.ConsoleEnabled)
	case "boot_interface":
		return c.BootInterface
	case "tls_ciphers":
		return c.TlsCiphers
	case "has_tls_container":
		if c.HasTlsContainer == nil {
			return ""
		}
		return fmt.Sprintf("%t", *c.HasTlsContainer)
	default:
		return "set"
	}
}

// MarshalYAML exports a Policy in the service-keyed YAML shape Load expects.
func MarshalYAML(p *Policy) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	doc := map[string]interface{}{
		"version": p.Version,
	}
	if p.Version == "" {
		doc["version"] = "v1"
	}
	if p.Defaults.Workers != 0 || p.Defaults.Days != 0 || p.Defaults.Output != "" {
		defaults := map[string]interface{}{}
		if p.Defaults.Workers != 0 {
			defaults["workers"] = p.Defaults.Workers
		}
		if p.Defaults.Days != 0 {
			defaults["days"] = p.Defaults.Days
		}
		if p.Defaults.Output != "" {
			defaults["output"] = p.Defaults.Output
		}
		doc["defaults"] = defaults
	}

	// Group flat GetAllRules back into service buckets preserving Policies order.
	type ruleYAML map[string]interface{}
	grouped := map[string][]ruleYAML{}
	order := []string{}
	seen := map[string]bool{}

	appendRule := func(service string, rule Rule) {
		if service == "" {
			service = rule.Service
		}
		if !seen[service] {
			seen[service] = true
			order = append(order, service)
		}
		item := ruleYAML{
			"name":     rule.Name,
			"resource": rule.Resource,
			"action":   rule.Action,
			"check":    rule.Check,
		}
		if rule.Description != "" {
			item["description"] = rule.Description
		}
		if rule.Severity != "" {
			item["severity"] = rule.Severity
		}
		if rule.Category != "" {
			item["category"] = rule.Category
		}
		if rule.GuideRef != "" {
			item["guide_ref"] = rule.GuideRef
		}
		if rule.ActionTagName != "" {
			item["action_tag_name"] = rule.ActionTagName
		}
		if rule.TagName != "" {
			item["tag_name"] = rule.TagName
		}
		grouped[service] = append(grouped[service], item)
	}

	if len(p.Policies) > 0 {
		for _, sp := range p.Policies {
			for _, rule := range sp.Rules {
				svc := sp.Service
				if rule.Service != "" {
					svc = rule.Service
				}
				appendRule(svc, rule)
			}
		}
	} else {
		for _, rule := range p.GetAllRules() {
			appendRule(rule.Service, rule)
		}
	}

	policies := make([]map[string]interface{}, 0, len(order))
	for _, svc := range order {
		policies = append(policies, map[string]interface{}{svc: grouped[svc]})
	}
	doc["policies"] = policies

	if len(p.Composites) > 0 || len(p.GetAllCompositeRules()) > 0 {
		compOrder := []string{}
		compSeen := map[string]bool{}
		compGrouped := map[string][]map[string]interface{}{}
		addComp := func(service string, rule CompositeRule) {
			if service == "" {
				service = rule.Service
			}
			if !compSeen[service] {
				compSeen[service] = true
				compOrder = append(compOrder, service)
			}
			item := map[string]interface{}{
				"name":      rule.Name,
				"service":   service,
				"resources": rule.Resources,
				"check":     rule.Check,
				"action":    rule.Action,
			}
			if rule.Description != "" {
				item["description"] = rule.Description
			}
			if rule.Severity != "" {
				item["severity"] = rule.Severity
			}
			if rule.Category != "" {
				item["category"] = rule.Category
			}
			if rule.GuideRef != "" {
				item["guide_ref"] = rule.GuideRef
			}
			compGrouped[service] = append(compGrouped[service], item)
		}
		if len(p.Composites) > 0 {
			for _, sp := range p.Composites {
				for _, rule := range sp.Rules {
					addComp(sp.Service, rule)
				}
			}
		} else {
			for _, rule := range p.GetAllCompositeRules() {
				addComp(rule.Service, rule)
			}
		}
		composites := make([]map[string]interface{}, 0, len(compOrder))
		for _, svc := range compOrder {
			composites = append(composites, map[string]interface{}{svc: compGrouped[svc]})
		}
		doc["composites"] = composites
	}

	return yaml.Marshal(doc)
}
