package services

import (
	"context"
	"fmt"

	discovery "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/members"
)

// GlanceImageDiscoverer discovers glance/image resources.
type GlanceImageDiscoverer struct{}

func (d *GlanceImageDiscoverer) ResourceType() string {
	return "image"
}

func (d *GlanceImageDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants // images.List already returns every image the caller is authorized to see

		pages, err := images.List(client, images.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		imageList, err := images.ExtractImages(pages)
		if err != nil {
			return
		}

		for _, img := range imageList {
			select {
			case <-ctx.Done():
				return
			case ch <- discovery.Job{
				Service:      "glance",
				ResourceType: "image",
				ResourceID:   img.ID,
				ProjectID:    img.Owner,
				Resource:     img,
			}:
			}
		}
	}()

	return ch, nil
}

// GlanceMemberDiscoverer discovers glance/member resources.
//
// Members are scoped per-image (a member is a project an image is shared
// with), so discovery first lists images and then lists each image's
// members.
type GlanceMemberDiscoverer struct{}

func (d *GlanceMemberDiscoverer) ResourceType() string {
	return "member"
}

func (d *GlanceMemberDiscoverer) Discover(ctx context.Context, client *gophercloud.ServiceClient, allTenants bool) (<-chan discovery.Job, error) {
	ch := make(chan discovery.Job)

	go func() {
		defer close(ch)
		_ = allTenants

		imagePages, err := images.List(client, images.ListOpts{}).AllPages()
		if err != nil {
			return
		}

		imageList, err := images.ExtractImages(imagePages)
		if err != nil {
			return
		}

		for _, img := range imageList {
			if ctx.Err() != nil {
				return
			}

			memberPages, err := members.List(client, img.ID).AllPages()
			if err != nil {
				continue
			}

			memberList, err := members.ExtractMembers(memberPages)
			if err != nil {
				continue
			}

			for _, m := range memberList {
				select {
				case <-ctx.Done():
					return
				case ch <- discovery.Job{
					Service:      "glance",
					ResourceType: "member",
					ResourceID:   fmt.Sprintf("%s/%s", m.ImageID, m.MemberID),
					ProjectID:    m.MemberID,
					Resource:     m,
				}:
				}
			}
		}
	}()

	return ch, nil
}
