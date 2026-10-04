package policy

import "testing"

func TestMarshalYAML_RoundTrip(t *testing.T) {
	src := []byte(`
version: v1
policies:
  - neutron:
    - name: unused-sg
      resource: security_group
      check:
        unused: true
      action: log
      severity: low
      category: hygiene
`)
	p, err := LoadBytes(src)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	out, err := MarshalYAML(p)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	p2, err := LoadBytes(out)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(p2.GetAllRules()) != 1 {
		t.Fatalf("rules = %d", len(p2.GetAllRules()))
	}
	if p2.GetAllRules()[0].Name != "unused-sg" {
		t.Fatalf("name = %q", p2.GetAllRules()[0].Name)
	}
}

func TestSummarizeChecks(t *testing.T) {
	sum := SummarizeChecks(CheckConditions{Unused: true, Status: "ERROR"})
	if len(sum) != 2 {
		t.Fatalf("len = %d", len(sum))
	}
}
