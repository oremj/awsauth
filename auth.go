// Signs requests as described in http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html.
package awsauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

const ISO8601Format = "20060102T150405Z"

func hashCanonicalRequest(r *http.Request) []byte {
	return hashSha256(bytes.NewBuffer(canonicalRequest(r)))
}

func canonicalRequest(r *http.Request) []byte {
	b := new(bytes.Buffer)

	b.WriteString(r.Method + "\n")

	b.Write(canonicalURI(r))
	b.WriteByte('\n')

	b.Write(canonicalQueryString(r))
	b.WriteByte('\n')

	b.Write(canonicalHeaders(r))
	b.WriteByte('\n')

	b.Write(signedHeaders(r))
	b.WriteByte('\n')

	b.Write(hashedRequestPayload(r))

	return b.Bytes()
}

func canonicalURI(r *http.Request) []byte {
	p := path.Clean(r.URL.RequestURI())
	if r.URL.RawQuery != "" {
		p = p[:len(p)-len(r.URL.RawQuery)-1]
	}
	return []byte(p)
}

func canonicalQueryString(r *http.Request) []byte {
	return []byte(r.URL.Query().Encode())
}

func canonicalHeaders(r *http.Request) []byte {
	h := make([]string, len(r.Header))

	i := 0
	for k, v := range r.Header {
		sort.Strings(v)
		h[i] = strings.ToLower(k) + ":" + strings.Join(v, ",")
		i++
	}
	sort.Strings(h)
	return []byte(strings.Join(h, "\n") + "\n")
}

func signedHeaders(r *http.Request) []byte {
	h := make([]string, len(r.Header))

	i := 0
	for k := range r.Header {
		h[i] = strings.ToLower(k)
		i++
	}
	sort.Strings(h)
	return []byte(strings.Join(h, ";"))
}

func hashSha256(b io.Reader) []byte {
	h := sha256.New()
	io.Copy(h, b)
	return []byte(fmt.Sprintf("%x", h.Sum(nil)))
}

func hashedRequestPayload(r *http.Request) []byte {
	buf := new(bytes.Buffer)
	if r.Body != nil {
		if _, err := buf.ReadFrom(r.Body); err != nil {
			panic(err)
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(buf.Bytes()))
	}

	return hashSha256(buf)
}

func hmacBytes(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

type AWSRequest struct {
	*http.Request
	AccessKey string
	Region    string
	Service   string
	SecretKey string
	date      time.Time
}

// Build new *AWSRequest
func NewAWSRequest(r *http.Request, key, secret string) (*AWSRequest, error) {
	parts := strings.Split(r.Host, ".")

	if len(parts) < 3 {
		return nil, errors.New("URL must have at least 2 dots.")
	}

	region := "us-east-1"
	service := parts[0]

	if len(parts) == 4 {
		region = parts[1]
	}

	aReq := &AWSRequest{
		Request:   r,
		Region:    region,
		AccessKey: key,
		SecretKey: secret,
		Service:   service,
		date:      time.Now().UTC(),
	}

	aReq.setDefaultHeaders()
	return aReq, nil
}

func (a *AWSRequest) setDefaultHeaders() {
	a.Header.Set("Host", a.Host)
	a.Header.Set("x-amz-date", a.date.Format(ISO8601Format))

	if a.Method == "POST" {
		a.Header.Set("Content-type", "application/x-www-form-urlencoded; charset=utf-8")
	}
}

func (a *AWSRequest) stringToSign() []byte {
	a.setDefaultHeaders()

	hashedReq := hashCanonicalRequest(a.Request)
	buf := new(bytes.Buffer)
	buf.WriteString("AWS4-HMAC-SHA256\n")
	buf.WriteString(a.date.Format(ISO8601Format) + "\n")

	buf.Write(a.credentialScope())
	buf.WriteByte('\n')

	buf.Write(hashedReq)

	return buf.Bytes()
}

func (a *AWSRequest) credentialScope() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(a.date.Format("20060102"))
	buf.WriteString("/" + a.Region + "/" + a.Service + "/aws4_request")
	return buf.Bytes()
}

func (a *AWSRequest) signingKey() []byte {
	kDate := hmacBytes([]byte("AWS4"+a.SecretKey), []byte(a.date.Format("20060102")))
	kRegion := hmacBytes(kDate, []byte(a.Region))
	kService := hmacBytes(kRegion, []byte(a.Service))
	return hmacBytes(kService, []byte("aws4_request"))
}

// Generate request signature.
func (a *AWSRequest) Signature() string {
	s2s := a.stringToSign()

	key := a.signingKey()
	return fmt.Sprintf("%x", hmacBytes(key, s2s))
}

// Add Authorization header to wrapped *http.Request
func (a *AWSRequest) Sign() {
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", a.AccessKey, a.credentialScope(), signedHeaders(a.Request), a.Signature())

	a.Header.Set("Authorization", authHeader)
}
