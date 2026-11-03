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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// Requests and signatures from the AWS SigV4 test suite
// (github.com/awslabs/aws-c-auth, tests/aws-signing-test-suite/v4).
func TestSignV4Vectors(t *testing.T) {
	const stsToken = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==" //nolint:gosec // published test vector
	cases := map[string]struct {
		method, body, token, signed, signature string
		headers                                map[string]string
	}{
		"get-vanilla": {
			method: http.MethodGet, signed: "host;x-amz-date",
			signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		"get-vanilla-with-session-token": { //nolint:gosec // published test vector
			method: http.MethodGet, token: "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267",
			signed:    "host;x-amz-date;x-amz-security-token",
			signature: "07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8",
		},
		"post-sts-header-before": {
			method: http.MethodPost, token: stsToken, signed: "host;x-amz-date;x-amz-security-token",
			signature: "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead",
		},
		"post-header-key-sort": {
			method: http.MethodPost, headers: map[string]string{"My-Header1": "value1"},
			signed:    "host;my-header1;x-amz-date",
			signature: "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c",
		},
		"post-x-www-form-urlencoded": {
			method: http.MethodPost, body: "Param1=value1",
			headers: map[string]string{
				"Content-Type": formType, "Content-Length": "13",
				"X-Amz-Content-Sha256": "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
			},
			signed:    "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
			signature: "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
		},
	}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for tcName, tc := range cases {
		t.Run(tcName, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://example.amazonaws.com/", strings.NewReader(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			c := awsCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: tc.token} //nolint:gosec // published test vector
			signV4(req, []byte(tc.body), c, "us-east-1", "service", now)
			want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=" +
				tc.signed + ", Signature=" + tc.signature
			if got := req.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization\n got %s\nwant %s", got, want)
			}
		})
	}
}

//nolint:gosec // fake credentials
const (
	awsSAToken   = "eyJ.aws-projected-token.sig"
	awsAccessKey = "ASIAFAKEACCESSKEY"
	awsSecretKey = "fake-aws-secret-access-key"
	awsSession   = "fake-aws-session-token"
	ecrPassword  = "fake-ecr-registry-password"
	awsRole      = "arn:aws:iam::123456789012:role/tagwarden-sync"
	awsRegion    = "eu-west-1"
)

const (
	formType = "application/x-www-form-urlencoded"
	certPEM  = "CERTIFICATE"
	notECR   = "is not an Amazon ECR private registry host"
)

// awsFakes is AWS STS and an Amazon ECR API plus registry that accepts
// only the password from GetAuthorizationToken. All use TLS.
type awsFakes struct {
	sts, ecr *httptest.Server
	repo     name.Repository
	// stsStatus and ecrStatus replace the success answer when non-zero;
	// stsCode and ecrToken change the error code and the token.
	stsStatus, ecrStatus atomic.Int32
	stsCode, ecrToken    atomic.Value
	stsForm              atomic.Value
	stsAuth              atomic.Bool
	ecrRequest           atomic.Value
	ecrHits              atomic.Int32
}

func newAWSFakes(t *testing.T) *awsFakes {
	t.Helper()
	f := &awsFakes{}
	f.stsCode.Store("InvalidIdentityToken")
	f.ecrToken.Store(base64.StdEncoding.EncodeToString([]byte("AWS:" + ecrPassword)))
	f.sts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Content-Type") != formType {
			t.Errorf("STS: %s %s with %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		f.stsAuth.Store(r.Header.Get("Authorization") != "")
		_ = r.ParseForm()
		f.stsForm.Store(r.PostForm)
		switch s := int(f.stsStatus.Load()); s {
		case 0:
			_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <SessionToken>%s</SessionToken><SecretAccessKey>%s</SecretAccessKey>
      <Expiration>2030-01-01T00:15:00Z</Expiration><AccessKeyId>%s</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`, awsSession, awsSecretKey, awsAccessKey)
		case http.StatusTemporaryRedirect:
			http.Redirect(w, r, f.ecr.URL+"/stolen", s)
		default:
			// STS may echo request details in the message.
			w.WriteHeader(s)
			_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>token %s</Message></Error></ErrorResponse>`,
				f.stsCode.Load(), awsSAToken)
		}
	}))
	t.Cleanup(f.sts.Close)
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	f.ecr = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.ecrHits.Add(1)
		if r.Header.Get("X-Amz-Target") != "" {
			body, _ := io.ReadAll(r.Body)
			f.ecrRequest.Store(checkECRRequest(r, body))
			if s := int(f.ecrStatus.Load()); s != 0 {
				w.WriteHeader(s)
				_, _ = fmt.Fprintf(w, `{"__type":"com.amazonaws.ecr#AccessDeniedException","message":"denied for %s"}`, awsSession)
				return
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_ = json.NewEncoder(w).Encode(map[string]any{"authorizationData": []map[string]any{{
				"authorizationToken": f.ecrToken.Load(), "expiresAt": 1.8934596e9, "proxyEndpoint": "https://" + r.Host,
			}}})
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "AWS" || p != ecrPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.ecr.Close)
	var err error
	if f.repo, err = name.NewRepository(strings.TrimPrefix(f.ecr.URL, "https://")+"/team/app", name.StrictValidation); err != nil {
		t.Fatal(err)
	}
	return f
}

var authorization = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$`)

// checkECRRequest returns "" when r is a GetAuthorizationToken request
// signed with the STS credentials, otherwise what is wrong.
func checkECRRequest(r *http.Request, body []byte) string {
	m := authorization.FindStringSubmatch(r.Header.Get("Authorization"))
	switch {
	case r.Method != http.MethodPost || r.URL.Path != "/" || string(body) != "{}":
		return fmt.Sprintf("%s %s %q", r.Method, r.URL.Path, body)
	case r.Header.Get("Content-Type") != "application/x-amz-json-1.1" ||
		r.Header.Get("X-Amz-Target") != "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken":
		return "headers " + r.Header.Get("Content-Type") + " " + r.Header.Get("X-Amz-Target")
	case r.Header.Get("X-Amz-Security-Token") != awsSession:
		return "no session token"
	case m == nil || m[1] != awsAccessKey || m[3] != awsRegion || m[4] != "ecr" ||
		m[5] != "content-type;host;x-amz-date;x-amz-security-token;x-amz-target":
		return "Authorization " + r.Header.Get("Authorization")
	}
	// Sign the signed headers again with the secret key.
	stamp, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || stamp.Format("20060102") != m[2] {
		return "X-Amz-Date " + r.Header.Get("X-Amz-Date")
	}
	again, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.Path, nil) //nolint:gosec // never sent
	for h := range strings.SplitSeq(m[5], ";") {
		if h != "host" && h != "x-amz-date" && h != "x-amz-security-token" {
			again.Header.Set(h, r.Header.Get(h))
		}
	}
	signV4(again, body, awsCredentials{AccessKeyID: awsAccessKey, SecretAccessKey: awsSecretKey, SessionToken: awsSession}, awsRegion, "ecr", stamp)
	if again.Header.Get("Authorization") != r.Header.Get("Authorization") {
		return "signature mismatch"
	}
	return ""
}

// remoteOpts reach the fake registry directly, as the test.
func (f *awsFakes) remoteOpts() []remote.Option {
	pool := x509.NewCertPool()
	pool.AddCert(f.ecr.Certificate())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return []remote.Option{remote.WithTransport(tr), remote.WithAuth(&authn.Basic{Username: "AWS", Password: ecrPassword})}
}

// awsEnv writes the token file, points the Job at the fakes, trusts them
// through the proxy CA file and sets auth ("targetAuth" or "sourceAuth").
func (f *awsFakes) awsEnv(t *testing.T, e *env, source name.Repository, auth string) {
	t.Helper()
	e.opts.awsToken = filepath.Join(e.dir, "aws-token")
	e.write(t, e.opts.awsToken, awsSAToken+"\n")
	e.opts.awsSTS, e.opts.awsECR = f.sts.URL+"/", f.ecr.URL+"/"
	e.opts.proxyCA = filepath.Join(e.dir, "proxy-ca.crt")
	e.write(t, e.opts.proxyCA, string(pem.EncodeToMemory(&pem.Block{Type: certPEM, Bytes: f.sts.Certificate().Raw})))
	e.writeSpec(t, source.String(), fmt.Sprintf(`"allowedSources":[%s],%q:%q,"aws":{"roleARN":%q,"region":%q}`,
		strconv.Quote(source.RegistryStr()), auth, syncspec.AuthAWSWorkloadIdentity, awsRole, awsRegion))
}

func (f *awsFakes) assertRequests(t *testing.T) {
	t.Helper()
	form, _ := f.stsForm.Load().(url.Values)
	want := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {awsRole},
		"RoleSessionName":  {roleSessionName(syncspec.Mirror{Namespace: "team-a", Name: "app"})},
		"WebIdentityToken": {awsSAToken}, "DurationSeconds": {"3600"},
	}
	if form.Encode() != want.Encode() || f.stsAuth.Load() {
		t.Fatalf("STS form %v, signed %v", form, f.stsAuth.Load())
	}
	if msg, _ := f.ecrRequest.Load().(string); msg != "" {
		t.Fatalf("ECR request: %s", msg)
	}
}

func assertNoAWSSecrets(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, s := range []string{awsSAToken, awsAccessKey, awsSecretKey, awsSession, ecrPassword, "aws-projected-token"} {
			if strings.Contains(o, s) {
				t.Fatalf("secret in output: %s", o)
			}
		}
	}
}

func TestRoleSessionName(t *testing.T) {
	n := roleSessionName(syncspec.Mirror{Namespace: strings.Repeat("n", 63), Name: strings.Repeat("m", 253)})
	if !regexp.MustCompile(`^tagwarden-[0-9a-f]{16}$`).MatchString(n) {
		t.Fatalf("session name %q", n)
	}
}

func TestRunAWSTarget(t *testing.T) {
	f := newAWSFakes(t)
	src := newRegistry(t, false)
	pushImages(t, src, "v1.0.0", v110)
	e := newEnv(t, src, f.repo, password)
	e.opts.targetAuth = filepath.Join(e.dir, "missing", "auth.json")
	f.awsEnv(t, e, src, "targetAuth")

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":2`) {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	f.assertRequests(t)
	tags, err := remote.List(f.repo, f.remoteOpts()...)
	if err != nil || len(tags) != 2 {
		t.Fatalf("target tags %v: %v", tags, err)
	}
	assertNoAWSSecrets(t, out, msg)
}

func TestRunAWSSource(t *testing.T) {
	f := newAWSFakes(t)
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(f.repo.Tag("v1.0.0"), img, f.remoteOpts()...); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, f.repo, newRegistry(t, true), password)
	f.awsEnv(t, e, f.repo, "sourceAuth")

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":1`) {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	f.assertRequests(t)
	assertNoAWSSecrets(t, out, msg)
}

func TestRunAWSErrors(t *testing.T) {
	cases := map[string]struct {
		setup func(f *awsFakes, e *env)
		code  int
		want  string
	}{
		"STS invalid token": {
			func(f *awsFakes, _ *env) { f.stsStatus.Store(http.StatusBadRequest) },
			syncspec.ExitConfig, "target credentials: AWS STS AssumeRoleWithWebIdentity: HTTP 400 InvalidIdentityToken",
		},
		"STS access denied": {
			func(f *awsFakes, _ *env) { f.stsStatus.Store(http.StatusForbidden); f.stsCode.Store("AccessDenied") },
			syncspec.ExitConfig, "AWS STS AssumeRoleWithWebIdentity: HTTP 403 AccessDenied",
		},
		"STS cannot reach the IdP": {
			func(f *awsFakes, _ *env) {
				f.stsStatus.Store(http.StatusBadRequest)
				f.stsCode.Store("IDPCommunicationError")
			},
			syncspec.ExitSyncFailed, "HTTP 400 IDPCommunicationError",
		},
		"STS unavailable": {
			func(f *awsFakes, _ *env) { f.stsStatus.Store(http.StatusServiceUnavailable) },
			syncspec.ExitSyncFailed, "AWS STS AssumeRoleWithWebIdentity: HTTP 503",
		},
		"STS redirect": {
			func(f *awsFakes, _ *env) { f.stsStatus.Store(http.StatusTemporaryRedirect) },
			syncspec.ExitConfig, "AWS STS AssumeRoleWithWebIdentity: HTTP 307",
		},
		"ECR access denied": {
			func(f *awsFakes, _ *env) { f.ecrStatus.Store(http.StatusBadRequest) },
			syncspec.ExitConfig, "target credentials: Amazon ECR GetAuthorizationToken: HTTP 400 AccessDeniedException",
		},
		"ECR unavailable": {
			func(f *awsFakes, _ *env) { f.ecrStatus.Store(http.StatusInternalServerError) },
			syncspec.ExitSyncFailed, "Amazon ECR GetAuthorizationToken: HTTP 500",
		},
		"ECR token without user": {
			func(f *awsFakes, _ *env) { f.ecrToken.Store(base64.StdEncoding.EncodeToString([]byte(ecrPassword))) },
			syncspec.ExitConfig, "Amazon ECR GetAuthorizationToken: invalid authorization token",
		},
		"no token file": {
			func(_ *awsFakes, e *env) { e.opts.awsToken = filepath.Join(e.dir, "missing", "token") },
			syncspec.ExitConfig, "projected ServiceAccount token",
		},
	}
	for tcName, tc := range cases {
		t.Run(tcName, func(t *testing.T) {
			f := newAWSFakes(t)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			f.awsEnv(t, e, src, "targetAuth")
			tc.setup(f, e)
			code, out, msg := e.run(t)
			if code != tc.code || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if tcName == "STS redirect" && f.ecrHits.Load() != 0 {
				t.Fatal("the token request followed the redirect")
			}
			assertNoAWSSecrets(t, out, msg)
		})
	}
}

// Tokens go only to ECR hosts in the role's region: anything else is a
// config error before any token request.
func TestRunAWSRefusesHosts(t *testing.T) {
	cases := map[string]struct{ target, want string }{
		"non-ECR target":   {"other.example.internal/team/app", notECR},
		"public ECR":       {"public.ecr.aws/team/app", notECR},
		"dual-stack ECR":   {"123456789012.dkr-ecr.eu-west-1.on.aws/team/app", notECR},
		"other region":     {"123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app", "registry region us-east-1 does not match workloadIdentity.aws.region eu-west-1"},
		"China suffix":     {"123456789012.dkr.ecr.eu-west-1.amazonaws.com.cn/team/app", notECR},
		"look-alike host":  {"123456789012.dkr.ecr.eu-west-1.amazonaws.com.example.internal/team/app", notECR},
		"non-default port": {"123456789012.dkr.ecr.eu-west-1.amazonaws.com:5000/team/app", notECR},
	}
	for tcName, tc := range cases {
		t.Run(tcName, func(t *testing.T) {
			f := newAWSFakes(t)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			e.target = tc.target
			f.awsEnv(t, e, src, "targetAuth")
			code, out, msg := e.run(t)
			if code != syncspec.ExitConfig || !strings.Contains(msg, "target credentials: ") || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if f.stsForm.Load() != nil || f.ecrHits.Load() != 0 {
				t.Fatal("a token request was sent")
			}
		})
	}
}
