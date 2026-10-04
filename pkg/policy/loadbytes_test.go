package policy

import "testing"

func TestLoadBytes_Minimal(t *testing.T) {
	yaml := []byte(`
version: v1
policies:
  - neutron:
    - name: unused-sg
      resource: security_group
      check:
        unused: true
      action: log
`)
	p, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if got := len(p.GetAllRules()); got != 1 {
		t.Fatalf("GetAllRules() = %d, want 1", got)
	}
	if p.GetAllRules()[0].Service != "neutron" {
		t.Fatalf("service = %q, want neutron", p.GetAllRules()[0].Service)
	}
}
