package cloudtrail

type ResponseElements struct {
	PolicyName    string        `json:"policyName,omitempty"`
	PolicyVersion PolicyVersion `json:"policyVersion,omitempty"`
}
