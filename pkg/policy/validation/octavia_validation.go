package validation
type OctaviaValidator struct{}
func (v *OctaviaValidator) ServiceName() string { return "octavia" }
func (v *OctaviaValidator) ValidateResource(check interface{}, resourceType, ruleName string) error { return nil }
func init() {}
