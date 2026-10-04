package barbican

import "strings"

// classifySecretRisk maps Barbican secret_type to a semantic risk tier.
// Rotation freshness still uses Updated/Created — the API has no rotation field.
func classifySecretRisk(secretType string) string {
	switch strings.ToLower(strings.TrimSpace(secretType)) {
	case "private", "certificate", "public-key":
		return "high"
	case "passphrase", "symmetric":
		return "medium"
	default:
		return "low"
	}
}
