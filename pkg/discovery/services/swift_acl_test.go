package services

import "testing"

func TestACLAllowsWorldRead(t *testing.T) {
	if !ACLAllowsWorldRead([]string{".r:*,.rlistings"}) {
		t.Fatal("expected world read for .r:* ACL")
	}
	if ACLAllowsWorldRead([]string{".r:tenant123"}) {
		t.Fatal("expected no world read for tenant-scoped ACL")
	}
}

func TestACLAllowsWorldWrite(t *testing.T) {
	if !ACLAllowsWorldWrite([]string{".w:*"}) {
		t.Fatal("expected world write for .w:* ACL")
	}
	if ACLAllowsWorldWrite([]string{".w:tenant123"}) {
		t.Fatal("expected no world write for tenant-scoped ACL")
	}
}
