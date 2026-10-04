package keystone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

func serviceClientFromContext(ctx context.Context) (*gophercloud.ServiceClient, error) {
	raw, ok := audit.ClientFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("service client not available in context")
	}
	c, ok := raw.(*gophercloud.ServiceClient)
	if !ok {
		return nil, fmt.Errorf("expected *gophercloud.ServiceClient, got %T", raw)
	}
	return c, nil
}

func userMFAEnabled(u users.User) bool {
	return parseBoolOption(u.Options["multi_factor_auth_enabled"])
}

func userIsServiceAccount(u users.User) bool {
	if t, ok := u.Extra["type"].(string); ok && strings.EqualFold(t, "service") {
		return true
	}
	// Legacy deployments sometimes mark service users in description/name.
	name := strings.ToLower(u.Name)
	for _, svc := range []string{"nova", "cinder", "glance", "neutron", "keystone", "heat", "swift"} {
		if name == svc {
			return true
		}
	}
	return false
}

func listGroupUsers(ctx context.Context, groupID string) ([]users.User, error) {
	c, err := serviceClientFromContext(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.Get(c.ServiceURL("groups", groupID, "users"), nil, &gophercloud.RequestOpts{
		OkCodes: []int{http.StatusOK},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var payload struct {
		Users []users.User `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Users, nil
}

func userAdminViaGroup(ctx context.Context, userID string) (bool, string, error) {
	c, err := serviceClientFromContext(ctx)
	if err != nil {
		return false, "", err
	}

	effective := true
	includeNames := true
	pages, err := roles.ListAssignments(c, roles.ListAssignmentsOpts{
		UserID:       userID,
		Effective:    &effective,
		IncludeNames: &includeNames,
	}).AllPages()
	if err != nil {
		return false, "", err
	}
	assignments, err := roles.ExtractRoleAssignments(pages)
	if err != nil {
		return false, "", err
	}
	for _, as := range assignments {
		if as.Group.ID == "" {
			continue
		}
		if strings.EqualFold(as.Role.Name, "admin") {
			return true, as.Group.Name, nil
		}
	}
	return false, "", nil
}
