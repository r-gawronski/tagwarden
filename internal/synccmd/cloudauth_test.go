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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

//nolint:gosec // fake tokens
const (
	accessToken = "access_token"
	saToken     = "eyJ.projected-sa-token.sig"
	entraToken  = "eyJ.entra-access-token.sig"
	acrRefresh  = "eyJ.acr-refresh-token.sig"
	clientID    = "11111111-1111-1111-1111-111111111111"
	tenantID    = "22222222-2222-2222-2222-222222222222"
)

// azureFakes is a Microsoft Entra token endpoint and an Azure Container
// Registry that accepts only the exchanged refresh token. Both use TLS.
type azureFakes struct {
	entra, acr *httptest.Server
	repo       name.Repository
	// entraStatus and acrStatus replace the success answer when non-zero.
	entraStatus, acrStatus atomic.Int32
	entraForm, acrForm     atomic.Value
	acrHits                atomic.Int32
}

func newAzureFakes(t *testing.T) *azureFakes {
	t.Helper()
	f := &azureFakes{}
	form := func(r *http.Request) url.Values {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("%s %s with %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		_ = r.ParseForm()
		return r.PostForm
	}
	f.entra = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+tenantID+"/oauth2/v2.0/token" {
			http.NotFound(w, r)
			return
		}
		f.entraForm.Store(form(r))
		switch s := int(f.entraStatus.Load()); s {
		case 0:
			_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": 3599, accessToken: entraToken})
		case http.StatusTemporaryRedirect:
			http.Redirect(w, r, f.acr.URL+"/stolen", s)
		default:
			// Entra may echo request details in the description.
			w.WriteHeader(s)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_client", "error_description": "AADSTS700016: assertion " + saToken, "error_codes": []int{700016},
			})
		}
	}))
	t.Cleanup(f.entra.Close)
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	f.acr = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.acrHits.Add(1)
		if r.URL.Path == "/oauth2/exchange" {
			f.acrForm.Store(form(r))
			if s := int(f.acrStatus.Load()); s != 0 {
				w.WriteHeader(s)
				_, _ = fmt.Fprintf(w, `{"errors":[{"code":"UNAUTHORIZED","message":%q}]}`, entraToken)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": acrRefresh})
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != acrUser || p != acrRefresh {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.acr.Close)
	var err error
	if f.repo, err = name.NewRepository(strings.TrimPrefix(f.acr.URL, "https://")+"/team/app", name.StrictValidation); err != nil {
		t.Fatal(err)
	}
	return f
}

// remoteOpts reach the fake registry directly, as the test.
func (f *azureFakes) remoteOpts() []remote.Option {
	pool := x509.NewCertPool()
	pool.AddCert(f.acr.Certificate())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return []remote.Option{remote.WithTransport(tr), remote.WithAuth(&authn.Basic{Username: acrUser, Password: acrRefresh})}
}

// azureEnv writes the token file, trusts the fakes through the proxy CA
// file and sets auth ("targetAuth" or "sourceAuth") in the spec.
func (f *azureFakes) azureEnv(t *testing.T, e *env, source name.Repository, auth string) {
	t.Helper()
	e.opts.azureToken = filepath.Join(e.dir, "token")
	e.write(t, e.opts.azureToken, saToken+"\n")
	// httptest TLS servers share one certificate.
	e.opts.proxyCA = filepath.Join(e.dir, "proxy-ca.crt")
	e.write(t, e.opts.proxyCA, string(pem.EncodeToMemory(&pem.Block{Type: certPEM, Bytes: f.entra.Certificate().Raw})))
	e.writeSpec(t, source.String(), fmt.Sprintf(`"allowedSources":[%s],%q:%q,
		"azure":{"clientID":%q,"tenantID":%q,"authorityHost":%q}`,
		strconv.Quote(source.RegistryStr()), auth, syncspec.AuthAzureWorkloadIdentity,
		clientID, tenantID, f.entra.URL+"/"))
}

func (f *azureFakes) assertRequests(t *testing.T) {
	t.Helper()
	ef, _ := f.entraForm.Load().(url.Values)
	want := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {clientID}, "scope": {syncspec.AzureScope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {saToken},
	}
	if ef.Encode() != want.Encode() {
		t.Fatalf("Entra form %v", ef)
	}
	af, _ := f.acrForm.Load().(url.Values)
	want = url.Values{
		"grant_type": {accessToken}, "service": {f.repo.RegistryStr()}, "tenant": {tenantID}, accessToken: {entraToken},
	}
	if af.Encode() != want.Encode() {
		t.Fatalf("exchange form %v", af)
	}
}

func assertNoTokens(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, s := range []string{saToken, entraToken, acrRefresh, "projected-sa-token", "entra-access-token", "acr-refresh-token"} {
			if strings.Contains(o, s) {
				t.Fatalf("token in output: %s", o)
			}
		}
	}
}

func TestRunAzureTarget(t *testing.T) {
	f := newAzureFakes(t)
	src := newRegistry(t, false)
	pushImages(t, src, "v1.0.0", v110)
	e := newEnv(t, src, f.repo, password)
	e.opts.targetAuth = filepath.Join(e.dir, "missing", "auth.json")
	f.azureEnv(t, e, src, "targetAuth")

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":2`) {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	f.assertRequests(t)
	tags, err := remote.List(f.repo, f.remoteOpts()...)
	if err != nil || len(tags) != 2 {
		t.Fatalf("target tags %v: %v", tags, err)
	}
	assertNoTokens(t, out, msg)
}

func TestRunAzureSource(t *testing.T) {
	f := newAzureFakes(t)
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(f.repo.Tag("v1.0.0"), img, f.remoteOpts()...); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, f.repo, newRegistry(t, true), password)
	f.azureEnv(t, e, f.repo, "sourceAuth")

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":1`) {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	f.assertRequests(t)
	assertNoTokens(t, out, msg)
}

func TestRunAzureErrors(t *testing.T) {
	cases := map[string]struct {
		setup func(f *azureFakes, e *env)
		code  int
		want  string
	}{
		"Entra invalid_client": {
			func(f *azureFakes, _ *env) { f.entraStatus.Store(http.StatusBadRequest) },
			syncspec.ExitConfig, "target credentials: token request to Microsoft Entra ID: HTTP 400 invalid_client AADSTS700016",
		},
		"Entra unavailable": {
			func(f *azureFakes, _ *env) { f.entraStatus.Store(http.StatusServiceUnavailable) },
			syncspec.ExitSyncFailed, "token request to Microsoft Entra ID: HTTP 503",
		},
		"Entra redirect": {
			func(f *azureFakes, _ *env) { f.entraStatus.Store(http.StatusTemporaryRedirect) },
			syncspec.ExitConfig, "token request to Microsoft Entra ID: HTTP 307",
		},
		"ACR exchange refused": {
			func(f *azureFakes, _ *env) { f.acrStatus.Store(http.StatusUnauthorized) },
			syncspec.ExitConfig, "target credentials: registry token exchange: HTTP 401",
		},
		tcNoTokenFile: {
			func(_ *azureFakes, e *env) { e.opts.azureToken = filepath.Join(e.dir, "missing", "token") },
			syncspec.ExitConfig, msgProjectedToken,
		},
	}
	for tcName, tc := range cases {
		t.Run(tcName, func(t *testing.T) {
			f := newAzureFakes(t)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			f.azureEnv(t, e, src, "targetAuth")
			tc.setup(f, e)
			code, out, msg := e.run(t)
			if code != tc.code || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if tcName == "Entra redirect" && f.acrHits.Load() != 0 {
				t.Fatal("the token request followed the redirect")
			}
			assertNoTokens(t, out, msg)
		})
	}
}

// Tokens go only to ACR hosts and known authorities: anything else is a
// config error before any token request.
func TestRunAzureRefusesHosts(t *testing.T) {
	cases := map[string]func(f *azureFakes, e *env, src name.Repository){
		"non-ACR target": func(f *azureFakes, e *env, src name.Repository) {
			e.target = exampleTargetRepo
			f.azureEnv(t, e, src, "targetAuth")
		},
		"unknown authority": func(f *azureFakes, e *env, src name.Repository) {
			f.azureEnv(t, e, src, "targetAuth")
			b, err := os.ReadFile(e.spec)
			if err != nil {
				t.Fatal(err)
			}
			e.write(t, e.spec, strings.Replace(string(b), f.entra.URL+"/", "https://login.example.internal/", 1))
		},
	}
	for tcName, setup := range cases {
		t.Run(tcName, func(t *testing.T) {
			f := newAzureFakes(t)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			setup(f, e, src)
			code, out, msg := e.run(t)
			if code != syncspec.ExitConfig || !strings.Contains(msg, "target credentials: ") {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if f.entraForm.Load() != nil || f.acrHits.Load() != 0 {
				t.Fatal("a token request was sent")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The default port is dropped from the exchange URL and the service field.
func TestAzureExchangeDropsDefaultPort(t *testing.T) {
	var exchangeHost, service string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_ = r.ParseForm()
		body := `{"access_token":"a"}`
		if r.URL.Path == "/oauth2/exchange" {
			exchangeHost, service, body = r.URL.Host, r.PostForm.Get("service"), `{"refresh_token":"r"}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(saToken), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := name.NewRegistry("myregistry.azurecr.io:443", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	p := azureProvider{
		id:        syncspec.Azure{ClientID: clientID, TenantID: tenantID, AuthorityHost: syncspec.DefaultAzureAuthorityHost},
		tokenFile: token, client: &http.Client{Transport: rt},
	}
	if _, err := p.Authenticator(t.Context(), reg); err != nil {
		t.Fatal(err)
	}
	if exchangeHost != "myregistry.azurecr.io" || service != "myregistry.azurecr.io" {
		t.Fatalf("exchange host %q, service %q", exchangeHost, service)
	}
}
