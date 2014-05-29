package awsauth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const testAccessKey = "AKIDEXAMPLE"
const testSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

var reqDate, _ = time.Parse(ISO8601Format, "20110909T233600Z")

func buildTestRequest(t *testing.T) *AWSRequest {
	body := "Action=ListUsers&Version=2010-05-08"

	r, err := http.NewRequest("POST", "http://iam.amazonaws.com/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	awsR := NewAWSRequest(r, "us-east-1", testAccessKey, testSecret, "iam")
	awsR.SetDate(reqDate)
	return awsR
}

func TestCanonicalRequest(t *testing.T) {
	r := buildTestRequest(t)
	if string(hashCanonicalRequest(r.Request)) != "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2" {
		t.Error("incorrect canonical request hash")
	}
}

func TestStringToSign(t *testing.T) {
	r := buildTestRequest(t)
	if len(r.stringToSign()) != 134 {
		t.Error("string to sign is not the correct length")
	}
}

func TestSign(t *testing.T) {
	r := buildTestRequest(t)
	sig := r.Signature()

	if string(sig) != "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c" {
		t.Error("incorrect signature")
	}

	r.Sign()
	authHeader := r.Request.Header.Get("Authorization")
	if authHeader != "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c" {
		t.Errorf("incorrect Authorization header: ", authHeader)
	}
}
