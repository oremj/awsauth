package awsauth

import "net/http"

type AWSClient struct {
	Client *http.Client
	Creds  *Credentials
}

func NewAWSClientFromEnv(c *http.Client) *AWSClient {
	return &AWSClient{
		Client: c,
		Creds:  NewCredentialsFromEnv(),
	}
}

func (a *AWSClient) Do(req *http.Request) (*http.Response, error) {
	awsReq, err := NewAWSRequest(req, a.Creds)
	if err != nil {
		return nil, err
	}
	awsReq.Sign()
	return a.Client.Do(req)
}
