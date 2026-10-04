package swift

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
)

func init() {
	if err := audit.RegisterComposite(&CompositeAuditor{}); err != nil {
		panic(err)
	}
}

// CompositeAuditor evaluates Swift cross-resource composite patterns.
type CompositeAuditor struct{}

func (a *CompositeAuditor) Service() string { return "swift" }

func (a *CompositeAuditor) Check(resources map[string][]discovery.Job, rule *policy.CompositeRule) (*audit.Result, error) {
	pattern := swiftCompositePattern(rule)
	result := &audit.Result{
		RuleID:     rule.Name,
		Compliant:  true,
		ResourceID: "composite:" + pattern,
	}

	switch pattern {
	case "public_container_aged_object":
		return a.checkPublicContainerAgedObject(resources, rule, result)
	case "":
		return nil, fmt.Errorf("swift composite rule %q: missing check.pattern", rule.Name)
	default:
		return nil, fmt.Errorf("swift composite rule %q: unknown pattern %q", rule.Name, pattern)
	}
}

func (a *CompositeAuditor) Fix(resources map[string][]discovery.Job, rule *policy.CompositeRule) error {
	_ = resources
	if rule.Action == "log" {
		return nil
	}
	return fmt.Errorf("swift composite: action %q not implemented", rule.Action)
}

func swiftCompositePattern(rule *policy.CompositeRule) string {
	if rule.Check == nil {
		return ""
	}
	if p, ok := rule.Check["pattern"].(string); ok {
		return strings.TrimSpace(p)
	}
	if v, ok := rule.Check["public_container_aged_object"].(bool); ok && v {
		return "public_container_aged_object"
	}
	return ""
}

func (a *CompositeAuditor) checkPublicContainerAgedObject(
	resources map[string][]discovery.Job,
	rule *policy.CompositeRule,
	result *audit.Result,
) (*audit.Result, error) {
	ageStr, _ := rule.Check["age_gt"].(string)
	var maxAge time.Duration
	if ageStr != "" {
		cc := policy.CheckConditions{AgeGT: ageStr}
		d, err := cc.ParseAgeGT()
		if err != nil {
			return nil, fmt.Errorf("swift composite rule %q: parsing age_gt: %w", rule.Name, err)
		}
		maxAge = d
	}

	publicContainers := map[string]discoveryservices.ContainerWithACL{}
	for _, job := range resources["container"] {
		c, ok := job.Resource.(discoveryservices.ContainerWithACL)
		if !ok {
			continue
		}
		if discoveryservices.ACLAllowsWorldRead(c.ReadACL) {
			publicContainers[c.Name] = c
		}
	}

	for _, job := range resources["object"] {
		o, ok := job.Resource.(discoveryservices.ObjectWithContainer)
		if !ok {
			continue
		}
		if !o.ContainerPublicRead {
			if _, pub := publicContainers[o.ContainerName]; !pub {
				continue
			}
		}
		ts := o.LastModified
		if ts.IsZero() {
			continue
		}
		if maxAge > 0 && time.Since(ts) <= maxAge {
			continue
		}

		result.Compliant = false
		result.ResourceID = o.ContainerName + "/" + o.Name
		result.ResourceName = o.Name
		result.Observation = fmt.Sprintf(
			"public_container_aged_object: object %q in public container %q last modified %s",
			o.Name, o.ContainerName, ts.Format(time.RFC3339),
		)
		return result, nil
	}

	result.Observation = "public_container_aged_object: no exposed aged objects found"
	return result, nil
}
