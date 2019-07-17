package main

type ResponseElements struct {
	PolicyName    string        `json:"policyName"`
	PolicyVersion PolicyVersion `json:"policyVersion"`
}
