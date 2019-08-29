package pkg

type CloudTrailEvent struct {
	ErrorCode         string            `json:"errorCode"`
	EventID           string            `json:"eventID"`
	EventName         string            `json:"eventName"`
	EventTime         string            `json:"eventTime"`
	EventType         string            `json:"eventType"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  ResponseElements  `json:"responseElements"`
	UserIdentity      UserIdentity      `json:"userIdentity"`
}
