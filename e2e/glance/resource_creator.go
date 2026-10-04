//go:build e2e

package glance

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/imagedata"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

const testPrefix = "ospa-e2e-"

// CreateImage creates a small active Glance image for e2e tests.
func CreateImage(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	name := fmt.Sprintf("%simage-%d", testPrefix, time.Now().UnixNano())
	visibility := images.ImageVisibilityPrivate
	img, err := images.Create(client, images.CreateOpts{
		Name:            name,
		DiskFormat:      "raw",
		ContainerFormat: "bare",
		Visibility:      &visibility,
	}).Extract()
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}
	t.Logf("Created test image: %s (%s)", img.Name, img.ID)

	payload := bytes.NewReader([]byte("ospa-e2e-image"))
	if err := imagedata.Upload(client, img.ID, payload).ExtractErr(); err != nil {
		_ = images.Delete(client, img.ID).ExtractErr()
		t.Fatalf("Failed to upload test image data: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		current, getErr := images.Get(client, img.ID).Extract()
		if getErr == nil && string(current.Status) == "active" {
			break
		}
		if time.Now().After(deadline) {
			status := "?"
			if current != nil {
				status = string(current.Status)
			}
			_ = images.Delete(client, img.ID).ExtractErr()
			t.Fatalf("Timed out waiting for image %s to become active (status=%s err=%v)", img.ID, status, getErr)
		}
		time.Sleep(500 * time.Millisecond)
	}

	cleanup = func() {
		t.Logf("Cleaning up test image: %s", img.ID)
		if err := images.Delete(client, img.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete test image %s: %v", img.ID, err)
		}
	}
	return img.ID, cleanup
}

// CreateMember creates a shared-image membership. ResourceID matches discovery:
// "<imageID>/<memberProjectID>".
func CreateMember(t *testing.T, client *gophercloud.ServiceClient) (resourceID string, cleanup func()) {
	t.Helper()

	imageID, imageCleanup := CreateImage(t, client)

	// Membership requires shared visibility.
	shared := images.ImageVisibilityShared
	if _, err := images.Update(client, imageID, images.UpdateOpts{
		images.UpdateVisibility{Visibility: shared},
	}).Extract(); err != nil {
		imageCleanup()
		t.Fatalf("Failed to set image visibility shared: %v", err)
	}

	identity, err := openstack.NewIdentityV3(client.ProviderClient, gophercloud.EndpointOpts{})
	if err != nil {
		imageCleanup()
		t.Skipf("Cannot create identity client for glance member test: %v", err)
	}

	projName := fmt.Sprintf("%smember-proj-%d", testPrefix, time.Now().UnixNano())
	proj, err := projects.Create(identity, projects.CreateOpts{
		Name:        projName,
		Description: "OSPA e2e glance member project",
		Enabled:     gophercloud.Enabled,
	}).Extract()
	if err != nil {
		imageCleanup()
		t.Fatalf("Failed to create member project: %v", err)
	}

	mem, err := members.Create(client, imageID, proj.ID).Extract()
	if err != nil {
		_ = projects.Delete(identity, proj.ID).ExtractErr()
		imageCleanup()
		t.Fatalf("Failed to create image member: %v", err)
	}
	t.Logf("Created image member %s on image %s", mem.MemberID, imageID)

	cleanup = func() {
		t.Logf("Cleaning up image member %s", mem.MemberID)
		if err := members.Delete(client, imageID, mem.MemberID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete image member: %v", err)
		}
		if err := projects.Delete(identity, proj.ID).ExtractErr(); err != nil {
			t.Logf("Warning: failed to delete member project: %v", err)
		}
		imageCleanup()
	}
	return fmt.Sprintf("%s/%s", imageID, mem.MemberID), cleanup
}

// CleanupOrphans deletes leaked test images.
func CleanupOrphans(t *testing.T, client *gophercloud.ServiceClient) {
	t.Helper()
	all, err := images.List(client, images.ListOpts{}).AllPages()
	if err != nil {
		t.Logf("Warning: list images for orphan cleanup: %v", err)
		return
	}
	imgs, err := images.ExtractImages(all)
	if err != nil {
		t.Logf("Warning: extract images: %v", err)
		return
	}
	for _, img := range imgs {
		if strings.HasPrefix(img.Name, testPrefix) {
			t.Logf("Deleting orphan image %s (%s)", img.Name, img.ID)
			_ = images.Delete(client, img.ID).ExtractErr()
		}
	}
}
