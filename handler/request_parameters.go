package main

type RequestParameters struct {
	PolicyArn      string `json:"policyArn"`
	PolicyDocument string `json:"policyDocument"`
	PolicyName     string `json:"policyName"`
	RoleName       string `json:"roleName"`
	VersionId      string `json:"versionId"`
}
