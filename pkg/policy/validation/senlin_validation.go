package validation
type SenlinValidator struct{}
func (v *SenlinValidator) ServiceName() string { return "senlin" }
func (v *SenlinValidator) ValidateResource(check interface{}, resourceType, ruleName string) error { return nil }
func init() {}
