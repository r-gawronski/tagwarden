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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// garUser tells Artifact Registry that the password is an access token.
const garUser = "oauth2accesstoken"

// gcpProvider exchanges the projected ServiceAccount token for a federated
// Google access token at the Security Token Service and, with a service
// account email, for an access token of that service account.
type gcpProvider struct {
	id        syncspec.GCP
	tokenFile string
	client    *http.Client
	// stsURL and iamURL replace https://sts.googleapis.com and
	// https://iamcredentials.googleapis.com in tests; allowLoopback lets
	// the registry be on 127.0.0.1.
	stsURL, iamURL string
	allowLoopback  bool
}

func (g gcpProvider) Authenticator(ctx context.Context, reg name.Registry) (authn.Authenticator, error) {
	host := reg.RegistryStr()
	// The access token goes only to Artifact Registry (threat model T32).
	if !syncspec.GARHost(host) && !loopback(g.allowLoopback, host) {
		return nil, fmt.Errorf("%s is not a Google Artifact Registry host", host)
	}
	subject, err := readToken(g.tokenFile)
	if err != nil {
		return nil, err
	}
	const sts = "Google STS token exchange"
	var r struct {
		AccessToken string `json:"access_token"`
	}
	err = postJSON(ctx, g.client, sts, cmp.Or(g.stsURL, "https://sts.googleapis.com")+"/v1/token", "", stsRequest{ //nolint:gosec // token types, not credentials
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Audience:           g.id.Audience,
		Scope:              syncspec.GCPScope,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		SubjectToken:       string(subject),
	}, &r)
	if err != nil {
		return nil, err
	}
	if r.AccessToken == "" {
		return nil, fmt.Errorf("%s: no access_token in the response", sts)
	}
	token := r.AccessToken
	if email := g.id.ServiceAccountEmail; email != "" {
		const iam = "Google IAM generateAccessToken"
		var sa struct {
			AccessToken string `json:"accessToken"`
		}
		endpoint := cmp.Or(g.iamURL, "https://iamcredentials.googleapis.com") +
			"/v1/projects/-/serviceAccounts/" + url.PathEscape(email) + ":generateAccessToken"
		// A sync Job runs up to one hour (activeDeadlineSeconds).
		err = postJSON(ctx, g.client, iam, endpoint, token, struct {
			Scope    []string `json:"scope"`
			Lifetime string   `json:"lifetime"`
		}{[]string{syncspec.GCPScope}, "3600s"}, &sa)
		if err != nil {
			return nil, err
		}
		if sa.AccessToken == "" {
			return nil, fmt.Errorf("%s: no accessToken in the response", iam)
		}
		token = sa.AccessToken
	}
	return authn.FromConfig(authn.AuthConfig{Username: garUser, Password: token}), nil
}

// stsRequest is the JSON body of an STS token exchange.
type stsRequest struct {
	GrantType          string `json:"grantType"`
	Audience           string `json:"audience"`
	Scope              string `json:"scope"`
	RequestedTokenType string `json:"requestedTokenType"`
	SubjectTokenType   string `json:"subjectTokenType"`
	SubjectToken       string `json:"subjectToken"`
}

// googleStatus matches a Google API error status such as PERMISSION_DENIED.
var googleStatus = regexp.MustCompile(`^[A-Z_]{1,64}$`)

// postJSON posts body as JSON, with bearer as the access token when set,
// and decodes the answer into out. Errors carry the status code and the
// OAuth error or Google API status only.
func postJSON(ctx context.Context, c *http.Client, what, endpoint, bearer string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%s: invalid endpoint", what)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := send(c, what, req, func(b []byte) []string {
		var r struct{ Error json.RawMessage }
		_ = json.Unmarshal(b, &r)
		// STS answers {"error": "invalid_grant"}, the IAM API
		// {"error": {"status": "PERMISSION_DENIED"}}.
		var code string
		var api struct{ Status string }
		if json.Unmarshal(r.Error, &code) == nil && oauthError.MatchString(code) {
			return []string{code}
		}
		if json.Unmarshal(r.Error, &api) == nil && googleStatus.MatchString(api.Status) {
			return []string{api.Status}
		}
		return nil
	}, nil)
	if err != nil {
		return err
	}
	if json.Unmarshal(resp, out) != nil {
		return fmt.Errorf("%s: invalid response", what)
	}
	return nil
}
