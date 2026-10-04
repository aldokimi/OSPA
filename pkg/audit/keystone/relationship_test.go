package keystone

import (
	"testing"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

func TestUserIsServiceAccount(t *testing.T) {
	svc := users.User{Name: "nova", Extra: map[string]interface{}{"type": "service"}}
	if !userIsServiceAccount(svc) {
		t.Fatal("expected service account for nova user")
	}
	human := users.User{Name: "alice"}
	if userIsServiceAccount(human) {
		t.Fatal("expected non-service account for regular user")
	}
}

func TestUserMFAEnabled(t *testing.T) {
	u := users.User{Options: map[string]interface{}{"multi_factor_auth_enabled": "true"}}
	if !userMFAEnabled(u) {
		t.Fatal("expected MFA enabled")
	}
}
