package cloudtrail

type CloudTrailEvent struct {
	ErrorCode         string            `json:"errorCode,omitempty"`
	EventID           string            `json:"eventID,omitempty"`
	EventName         string            `json:"eventName,omitempty"`
	EventTime         string            `json:"eventTime,omitempty"`
	EventType         string            `json:"eventType,omitempty"`
	RequestParameters RequestParameters `json:"requestParameters,omitempty"`
	ResponseElements  ResponseElements  `json:"responseElements,omitempty"`
	UserIdentity      UserIdentity      `json:"userIdentity,omitempty"`
}
