package awsauth

import (
	"net/http"
	"os"
)

type AWSClient struct {
	AccessKey string
	SecretKey string
	Client    *http.Client
}

func NewAWSClientFromEnv(c *http.Client) *AWSClient {
	return &AWSClient{
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		Client:    c,
	}
}

func (a *AWSClient) Do(req *http.Request) (*http.Response, error) {
	awsReq, err := NewAWSRequest(req, a.AccessKey, a.SecretKey)
	if err != nil {
		return nil, err
	}
	awsReq.Sign()
	return a.Client.Do(req)
}
