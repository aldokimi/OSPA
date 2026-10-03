package validation
type ZaqarValidator struct{}
func (v *ZaqarValidator) ServiceName() string { return "zaqar" }
func (v *ZaqarValidator) ValidateResource(check interface{}, resourceType, ruleName string) error { return nil }
func init() {}
