package cloudtrail

type CloudTrailEvents struct {
	Records []CloudTrailEvent `json:"Records,omitempty"`
}
