package heat

import (
	"strings"
	"testing"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stackresources"
	"github.com/gophercloud/gophercloud/openstack/orchestration/v1/stacks"
)

func TestHeatComposite_Registered(t *testing.T) {
	if _, ok := audit.GetComposite("heat"); !ok {
		t.Fatal("expected heat CompositeAuditor to be registered")
	}
}

func TestHeatComposite_FailedStackRootCause(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"stack": {{
			Resource: stacks.ListedStack{
				ID:           "stack-1",
				Name:         "web",
				Status:       "CREATE_FAILED",
				StatusReason: "Resource CREATE failed",
			},
		}},
		"resource": {{
			Resource: discoveryservices.HeatResourceInStack{
				Resource: stackresources.Resource{
					Name:         "Server",
					Status:       "CREATE_FAILED",
					StatusReason: "No valid host",
				},
				StackName: "web",
			},
		}},
	}

	rule := &policy.CompositeRule{
		Name:      "failed-root",
		Resources: []string{"stack", "resource"},
		Check:     map[string]interface{}{"pattern": "failed_stack_root_cause"},
		Action:    "log",
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant")
	}
	if !strings.Contains(result.Observation, "failed_stack_root_cause") ||
		!strings.Contains(result.Observation, "Server") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}
