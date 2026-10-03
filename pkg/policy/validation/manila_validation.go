package validation

type ManillaValidator struct{}
func (v *ManillaValidator) ServiceName() string { return "manila" }
func (v *ManillaValidator) ValidateResource(check interface{}, resourceType, ruleName string) error { return nil }
func init() {}
