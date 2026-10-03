package validation
type TroveValidator struct{}
func (v *TroveValidator) ServiceName() string { return "trove" }
func (v *TroveValidator) ValidateResource(check interface{}, resourceType, ruleName string) error { return nil }
func init() {}
