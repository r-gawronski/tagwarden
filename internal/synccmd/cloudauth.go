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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// credentialProvider gets registry credentials from a cloud identity:
// Azure, AWS and Google Cloud.
type credentialProvider interface {
	Authenticator(ctx context.Context, reg name.Registry) (authn.Authenticator, error)
}

// cloudAuth authenticates to reg with the provider the spec names. Token
// calls go through rt, so the proxy, CAs, host checks and the startup
// window apply to them. Tokens stay in memory and never reach errors.
func cloudAuth(ctx context.Context, provider string, spec syncspec.Spec, o options, rt http.RoundTripper, reg name.Registry, what string) (authn.Authenticator, error) {
	client := &http.Client{
		Transport: rt,
		Timeout:   time.Minute,
		// A redirect would carry the token request to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var p credentialProvider
	switch provider {
	case syncspec.AuthAzureWorkloadIdentity:
		p = azureProvider{id: *spec.Azure, tokenFile: o.azureToken, client: client, allowLoopback: o.allowLoopback}
	case syncspec.AuthAWSWorkloadIdentity:
		p = awsProvider{
			id: *spec.AWS, tokenFile: o.awsToken, client: client, allowLoopback: o.allowLoopback,
			session: roleSessionName(spec.Mirror), stsURL: o.awsSTS, ecrURL: o.awsECR,
		}
	case syncspec.AuthGCPWorkloadIdentity:
		p = gcpProvider{
			id: *spec.GCP, tokenFile: o.gcpToken, client: client, allowLoopback: o.allowLoopback,
			stsURL: o.gcpSTS, iamURL: o.gcpIAM,
		}
	default:
		return nil, fmt.Errorf("%s credentials: unknown provider %q", what, provider)
	}
	a, err := p.Authenticator(ctx, reg)
	if err != nil {
		return nil, fmt.Errorf("%s credentials: %w", what, err)
	}
	return a, nil
}

// acrUser tells Azure Container Registry that the password is a refresh token.
const acrUser = "00000000-0000-0000-0000-000000000000"

// azureProvider exchanges the projected ServiceAccount token for a
// Microsoft Entra access token (client credentials with a federated
// assertion), then for an Azure Container Registry refresh token.
type azureProvider struct {
	id        syncspec.Azure
	tokenFile string
	client    *http.Client
	// allowLoopback lets tests use fakes on 127.0.0.1.
	allowLoopback bool
}

// loopback reports whether rawHost (host[:port] or a URL) is a loopback
// address and allow is set: tests use fakes on 127.0.0.1.
func loopback(allow bool, rawHost string) bool {
	if u, err := url.Parse(rawHost); err == nil && u.Host != "" {
		rawHost = u.Host
	}
	h, _, err := net.SplitHostPort(rawHost)
	if err != nil {
		h = rawHost
	}
	ip, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return allow && err == nil && ip.IsLoopback()
}

func (a azureProvider) Authenticator(ctx context.Context, reg name.Registry) (authn.Authenticator, error) {
	host := reg.RegistryStr()
	// The Entra token is sent only to Azure Container Registry, and the
	// projected token only to a known authority (threat model T27).
	if !syncspec.ACRHost(host) && !loopback(a.allowLoopback, host) {
		return nil, fmt.Errorf("%s is not an Azure Container Registry host", host)
	}
	if !syncspec.AzureAuthority(a.id.AuthorityHost) && !loopback(a.allowLoopback, a.id.AuthorityHost) {
		return nil, errors.New("authorityHost is not a known Microsoft Entra authority host")
	}
	assertion, err := readToken(a.tokenFile)
	if err != nil {
		return nil, err
	}
	entra := strings.TrimSuffix(a.id.AuthorityHost, "/") + "/" + a.id.TenantID + "/oauth2/v2.0/token"
	r, err := postForm(ctx, a.client, "token request to Microsoft Entra ID", entra, url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {a.id.ClientID},
		"scope":                 {syncspec.AzureScope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {string(assertion)},
	})
	if err != nil {
		return nil, err
	}
	if r.AccessToken == "" {
		return nil, errors.New("token request to Microsoft Entra ID: no access_token in the response")
	}
	// ACR names itself without the default port.
	host = strings.TrimSuffix(host, ":443")
	r, err = postForm(ctx, a.client, "registry token exchange", "https://"+host+"/oauth2/exchange", url.Values{
		"grant_type":   {"access_token"},
		"service":      {host},
		"tenant":       {a.id.TenantID},
		"access_token": {r.AccessToken},
	})
	if err != nil {
		return nil, err
	}
	if r.RefreshToken == "" {
		return nil, errors.New("registry token exchange: no refresh_token in the response")
	}
	return authn.FromConfig(authn.AuthConfig{Username: acrUser, Password: r.RefreshToken}), nil
}

// readToken reads the projected ServiceAccount token.
func readToken(file string) ([]byte, error) {
	b, err := os.ReadFile(file) //nolint:gosec // fixed mount path or a test file
	if err != nil {
		return nil, fmt.Errorf("projected ServiceAccount token: %w", err)
	}
	if b = bytes.TrimSpace(b); len(b) == 0 {
		return nil, errors.New("projected ServiceAccount token is empty")
	}
	return b, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorCodes   []int  `json:"error_codes"`
}

// oauthError matches an OAuth error code such as invalid_client.
var oauthError = regexp.MustCompile(`^[a-z_]{1,64}$`)

// postForm posts an OAuth form to endpoint and decodes the JSON answer.
// Errors carry the status code and the OAuth and Entra error codes only.
func postForm(ctx context.Context, c *http.Client, what, endpoint string, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("%s: invalid endpoint", what)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := send(c, what, req, func(b []byte) []string {
		var r tokenResponse
		_ = json.Unmarshal(b, &r)
		var codes []string
		if oauthError.MatchString(r.Error) {
			codes = append(codes, r.Error)
		}
		for _, code := range r.ErrorCodes[:min(3, len(r.ErrorCodes))] {
			codes = append(codes, fmt.Sprintf("AADSTS%d", code))
		}
		return codes
	}, nil)
	if err != nil {
		return tokenResponse{}, err
	}
	var r tokenResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return tokenResponse{}, fmt.Errorf("%s: invalid response", what)
	}
	return r, nil
}

// send sends a token request and returns the body of a 200 answer.
// Errors carry the status code and the codes that codesOf finds in the
// body, never the body or the request. A 4xx answer is a config error;
// 429, 5xx, network errors and a 4xx with a code for which retry holds
// are transient.
func send(c *http.Client, what string, req *http.Request, codesOf func([]byte) []string, retry func(code string) bool) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		err = fmt.Errorf("%s: %w", what, err)
		if errors.As(err, new(*registry.PolicyError)) {
			return nil, err
		}
		return nil, transientError{err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, transientError{fmt.Errorf("%s: reading the response: %w", what, err)}
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	codes := codesOf(body)
	err = errors.New(strings.Join(append([]string{fmt.Sprintf("%s: HTTP %d", what, resp.StatusCode)}, codes...), " "))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
		retry != nil && slices.ContainsFunc(codes, retry) {
		return nil, transientError{err}
	}
	return nil, err
}
