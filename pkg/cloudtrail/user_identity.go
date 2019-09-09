package cloudtrail

type UserIdentity struct {
	Type     string `json:"type,omitempty"`
	UserName string `json:"username,omitempty"`
}
