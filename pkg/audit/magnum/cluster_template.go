package magnum

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit/common"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud"
)

type clusterTemplateAdapter struct {
	t discoveryservices.MagnumClusterTemplate
}

func (a clusterTemplateAdapter) GetID() string           { return a.t.ID }
func (a clusterTemplateAdapter) GetName() string         { return a.t.Name }
func (a clusterTemplateAdapter) GetProjectID() string    { return "" }
func (a clusterTemplateAdapter) GetStatus() string       { return "" } // templates have no state field
func (a clusterTemplateAdapter) GetCreatedAt() time.Time { return a.t.CreatedAt }
func (a clusterTemplateAdapter) GetUpdatedAt() time.Time { return a.t.UpdatedAt }

// ClusterTemplateAuditor audits magnum/cluster_template resources.
//
// Allowed checks: age_gt, exempt_names, tls_disabled, network_driver
// Allowed actions: log, delete
//
// Note: cluster templates expose no status field, so status and unused are
// not offered.
type ClusterTemplateAuditor struct{}

func (a *ClusterTemplateAuditor) ResourceType() string {
	return "cluster_template"
}

func (a *ClusterTemplateAuditor) ImplementedChecks() []string {
	return []string{"age_gt", "exempt_names", "tls_disabled", "network_driver"}
}

func (a *ClusterTemplateAuditor) Check(ctx context.Context, resource interface{}, rule *policy.Rule) (*audit.Result, error) {
	_ = ctx

	t, ok := resource.(discoveryservices.MagnumClusterTemplate)
	if !ok {
		return nil, fmt.Errorf("expected discovery services MagnumClusterTemplate, got %T", resource)
	}

	adapter := clusterTemplateAdapter{t: t}
	result := common.BuildBaseResult(adapter, rule)

	exempt, err := common.RunCommonChecks(adapter, rule, result)
	if exempt || err != nil {
		return result, err
	}

	tlsHit := false
	if rule.Check.TlsDisabled != nil && t.TLSDisabled != *rule.Check.TlsDisabled {
		tlsHit = true
		result.Compliant = false
		result.Observation = fmt.Sprintf("cluster template tls_disabled is %t", t.TLSDisabled)
	}

	networkHit := false
	if rule.Check.NetworkDriver != "" && !strings.EqualFold(t.NetworkDriver, rule.Check.NetworkDriver) {
		networkHit = true
		result.Compliant = false
		result.Observation = fmt.Sprintf("cluster template network_driver is %q", t.NetworkDriver)
	}

	// #120 catalog outcome: insecure template networking posture.
	if tlsHit && networkHit {
		result.Observation = fmt.Sprintf(
			"insecure_template_inputs: tls_disabled=%t network_driver=%q coe=%q",
			t.TLSDisabled, t.NetworkDriver, t.COE,
		)
	}

	return result, nil
}

func (a *ClusterTemplateAuditor) Fix(ctx context.Context, client interface{}, resource interface{}, rule *policy.Rule) error {
	_ = ctx

	if rule.Action == "log" {
		return nil
	}

	c, ok := client.(*gophercloud.ServiceClient)
	if !ok {
		return fmt.Errorf("expected *gophercloud.ServiceClient, got %T", client)
	}

	tmpl, ok := resource.(discoveryservices.MagnumClusterTemplate)
	if !ok {
		return fmt.Errorf("expected discovery services MagnumClusterTemplate, got %T", resource)
	}

	switch rule.Action {
	case "delete":
		resp, err := c.Request("DELETE", c.ServiceURL("templates", tmpl.ID), &gophercloud.RequestOpts{
			OkCodes: []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		})
		if err != nil {
			return fmt.Errorf("deleting cluster template %s: %w", tmpl.Name, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return nil

	default:
		return fmt.Errorf("magnum/cluster_template: action %q not implemented", rule.Action)
	}
}
