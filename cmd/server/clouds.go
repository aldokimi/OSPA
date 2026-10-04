package main

import (
	"os"
	"sort"

	"github.com/gophercloud/utils/openstack/clientconfig"
)

// listCloudNames returns clouds.yaml names for opt-in local profiles only.
// The UI never auto-selects or connects these.
func listCloudNames() ([]string, error) {
	clouds, err := clientconfig.LoadCloudsYAML()
	if err != nil {
		// Missing clouds.yaml is not fatal for browsing the UI.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(clouds))
	for name := range clouds {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
