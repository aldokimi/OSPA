package barbican

import "testing"

func TestClassifySecretRisk(t *testing.T) {
	tests := map[string]string{
		"private":     "high",
		"certificate": "high",
		"passphrase":  "medium",
		"opaque":      "low",
		"":            "low",
	}
	for typ, want := range tests {
		if got := classifySecretRisk(typ); got != want {
			t.Fatalf("classifySecretRisk(%q) = %q, want %q", typ, got, want)
		}
	}
}
