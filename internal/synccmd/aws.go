/*
Copyright 2026 The Tagwarden Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package synccmd

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// awsProvider assumes the IAM role with the projected ServiceAccount token
// (STS AssumeRoleWithWebIdentity), then gets an Amazon ECR authorization
// token with the temporary credentials (SigV4-signed GetAuthorizationToken).
type awsProvider struct {
	id        syncspec.AWS
	tokenFile string
	client    *http.Client
	// session is the RoleSessionName, which CloudTrail shows.
	session string
	// stsURL and ecrURL replace the endpoints derived from the region in
	// tests; allowLoopback lets the registry be on 127.0.0.1.
	stsURL, ecrURL string
	allowLoopback  bool
}

// roleSessionName names the STS session after the mirror without
// disclosing it: tagwarden-<16 hex digits>, within the 64-character limit.
func roleSessionName(m syncspec.Mirror) string {
	sum := sha256.Sum256([]byte(m.Namespace + "/" + m.Name))
	return "tagwarden-" + hex.EncodeToString(sum[:8])
}

// awsCredentials are temporary STS credentials. They stay in memory.
type awsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
}

func (a awsProvider) Authenticator(ctx context.Context, reg name.Registry) (authn.Authenticator, error) {
	host := reg.RegistryStr()
	region, fips := a.id.Region, false
	// The projected token goes only to STS of the role's region and the
	// ECR token only to an ECR registry in that region (threat model T29).
	if !loopback(a.allowLoopback, host) {
		var ok bool
		if region, fips, ok = syncspec.ECRHost(host); !ok {
			return nil, fmt.Errorf("%s is not an Amazon ECR private registry host", host)
		}
		if region != a.id.Region {
			return nil, fmt.Errorf("registry region %s does not match workloadIdentity.aws.region %s", region, a.id.Region)
		}
	}
	token, err := readToken(a.tokenFile)
	if err != nil {
		return nil, err
	}
	suffix := syncspec.AWSDNSSuffix(region)
	stsURL := cmp.Or(a.stsURL, "https://sts."+region+"."+suffix+"/")
	ecrURL := cmp.Or(a.ecrURL, "https://api.ecr."+region+"."+suffix+"/")
	if fips {
		ecrURL = cmp.Or(a.ecrURL, "https://ecr-fips."+region+"."+suffix+"/")
	}
	creds, err := a.assumeRole(ctx, stsURL, token)
	if err != nil {
		return nil, err
	}
	user, password, err := a.authorizationToken(ctx, ecrURL, region, creds)
	if err != nil {
		return nil, err
	}
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: password}), nil
}

// awsCode matches an AWS error code such as InvalidIdentityToken.
var awsCode = regexp.MustCompile(`^[A-Za-z]{1,64}$`)

// stsRetry lists STS error codes that come with HTTP 400 but may pass on
// the next run.
func stsRetry(code string) bool { return code == "IDPCommunicationError" || code == "Throttling" }

func (a awsProvider) assumeRole(ctx context.Context, endpoint string, token []byte) (awsCredentials, error) {
	const what = "AWS STS AssumeRoleWithWebIdentity"
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {a.id.RoleARN},
		"RoleSessionName":  {a.session},
		"WebIdentityToken": {string(token)},
		// The ECR token may expire with the session, and a sync Job runs
		// up to one hour (activeDeadlineSeconds).
		"DurationSeconds": {"3600"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return awsCredentials{}, fmt.Errorf("%s: invalid endpoint", what)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := send(a.client, what, req, func(b []byte) []string {
		var r struct {
			Error struct{ Code string } `xml:"Error"`
		}
		if xml.Unmarshal(b, &r) == nil && awsCode.MatchString(r.Error.Code) {
			return []string{r.Error.Code}
		}
		return nil
	}, stsRetry)
	if err != nil {
		return awsCredentials{}, err
	}
	var r struct {
		Credentials awsCredentials `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return awsCredentials{}, fmt.Errorf("%s: invalid response", what)
	}
	if c := r.Credentials; c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return awsCredentials{}, fmt.Errorf("%s: no credentials in the response", what)
	}
	return r.Credentials, nil
}

func (a awsProvider) authorizationToken(ctx context.Context, endpoint, region string, c awsCredentials) (user, password string, err error) {
	const what = "Amazon ECR GetAuthorizationToken"
	body := []byte("{}")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("%s: invalid endpoint", what)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
	signV4(req, body, c, region, "ecr", time.Now())
	resp, err := send(a.client, what, req, func(b []byte) []string {
		var r struct {
			Type string `json:"__type"`
		}
		_ = json.Unmarshal(b, &r)
		// AWS JSON protocols may prefix the code with a namespace.
		if code := r.Type[strings.LastIndex(r.Type, "#")+1:]; awsCode.MatchString(code) {
			return []string{code}
		}
		return nil
	}, func(code string) bool { return code == "ThrottlingException" })
	if err != nil {
		return "", "", err
	}
	var r struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(resp, &r); err != nil || len(r.AuthorizationData) == 0 {
		return "", "", fmt.Errorf("%s: invalid response", what)
	}
	// The token is base64("AWS:<password>").
	dec, err := base64.StdEncoding.DecodeString(r.AuthorizationData[0].AuthorizationToken)
	user, password, ok := strings.Cut(string(dec), ":")
	if err != nil || !ok || user == "" || password == "" {
		return "", "", fmt.Errorf("%s: invalid authorization token", what)
	}
	return user, password, nil
}

// signV4 adds an AWS Signature Version 4 Authorization header to req,
// which has no query string. It signs host and every header set on req.
// With a session token it also sets and signs X-Amz-Security-Token.
func signV4(req *http.Request, body []byte, c awsCredentials, region, service string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", stamp)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, v := range req.Header {
		vals := make([]string, len(v))
		for i := range v {
			vals[i] = strings.Join(strings.Fields(v[i]), " ")
		}
		headers[strings.ToLower(k)] = strings.Join(vals, ",")
	}
	names := make([]string, 0, len(headers))
	var canonHeaders strings.Builder
	for k := range headers {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	payload := sha256.Sum256(body)
	canonical := strings.Join([]string{req.Method, path, "", canonHeaders.String(), signed, hex.EncodeToString(payload[:])}, "\n")
	hash := sha256.Sum256([]byte(canonical))
	scope := stamp[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	key := []byte("AWS4" + c.SecretAccessKey)
	for _, part := range []string{stamp[:8], region, service, "aws4_request", toSign} {
		key = hmacSHA256(key, part)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+hex.EncodeToString(key))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
