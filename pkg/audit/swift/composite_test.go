package swift

import (
	"strings"
	"testing"
	"time"

	discoveryservices "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
)

func TestCompositeAuditor_PublicContainerAgedObject(t *testing.T) {
	auditor := &CompositeAuditor{}
	resources := map[string][]discovery.Job{
		"container": {{
			Resource: discoveryservices.ContainerWithACL{
				Container: containers.Container{Name: "public"},
				ReadACL:   []string{".r:*,.rlistings"},
			},
		}},
		"object": {{
			Resource: discoveryservices.ObjectWithContainer{
				Object:              objects.Object{Name: "old.txt", LastModified: time.Now().Add(-72 * time.Hour)},
				ContainerName:       "public",
				ContainerPublicRead: true,
			},
		}},
	}

	rule := &policy.CompositeRule{
		Name: "exposed-old-objects",
		Check: map[string]interface{}{
			"pattern": "public_container_aged_object",
			"age_gt":  "1d",
		},
	}

	result, err := auditor.Check(resources, rule)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Compliant {
		t.Fatal("expected non-compliant for public container aged object")
	}
	if !strings.Contains(result.Observation, "public_container_aged_object") {
		t.Fatalf("unexpected observation: %q", result.Observation)
	}
}
