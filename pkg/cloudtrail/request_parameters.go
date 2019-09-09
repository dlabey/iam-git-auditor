package cloudtrail

type RequestParameters struct {
	PolicyArn      string `json:"policyArn,omitempty"`
	PolicyDocument string `json:"policyDocument,omitempty"`
	PolicyName     string `json:"policyName,omitempty"`
	RoleName       string `json:"roleName,omitempty"`
	VersionId      string `json:"versionId,omitempty"`
}
