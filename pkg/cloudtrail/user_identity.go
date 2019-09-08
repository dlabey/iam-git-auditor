package cloudtrail

type UserIdentity struct {
	Type     string `json:"type"`
	UserName string `json:"username"`
}
