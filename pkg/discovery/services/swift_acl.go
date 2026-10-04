package services

import (
	"strings"

	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
)

// ContainerWithACL carries list metadata plus Read/Write ACL headers from Get.
type ContainerWithACL struct {
	containers.Container
	ReadACL  []string
	WriteACL []string
}

// ACLAllowsWorldRead reports whether the container Read ACL grants anonymous access.
func ACLAllowsWorldRead(read []string) bool {
	for _, entry := range read {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, ".r:*") || strings.Contains(entry, ".rlistings") {
			return true
		}
	}
	return false
}

// ACLAllowsWorldWrite reports whether the container Write ACL grants anonymous write.
func ACLAllowsWorldWrite(write []string) bool {
	for _, entry := range write {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, ".w:*") {
			return true
		}
	}
	return false
}
