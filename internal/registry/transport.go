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

// Package registry builds the HTTP transport used to reach OCI registries
// through an egress proxy, with a custom CA bundle and optional mTLS.
package registry

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// Options configures NewTransport.
type Options struct {
	// CAPEM is added to the system roots, for example a TLS-inspecting proxy CA.
	CAPEM []byte
	// ProxyURL is used for every request except NoProxy hosts. When nil, the
	// HTTPS_PROXY, HTTP_PROXY and NO_PROXY environment variables apply.
	ProxyURL *url.URL
	// NoProxy uses NO_PROXY syntax: a host, a ".suffix" domain or a CIDR,
	// each with an optional port.
	NoProxy []string
	// ProxyUser and ProxyPassword are sent as Proxy-Authorization.
	ProxyUser, ProxyPassword string
	// ClientCert is presented for mTLS.
	ClientCert *tls.Certificate
}

// NewTransport returns a transport based on http.DefaultTransport. It trusts
// the system roots plus o.CAPEM and requires TLS 1.2 or later. Go never
// proxies requests to localhost or loopback addresses.
func NewTransport(o Options) (http.RoundTripper, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(o.CAPEM) > 0 && !pool.AppendCertsFromPEM(o.CAPEM) {
		return nil, errors.New("registry: CA bundle contains no PEM certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if o.ClientCert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*o.ClientCert}
	}
	if t.Proxy, err = proxyFunc(o); err != nil {
		return nil, err
	}
	return t, nil
}

func proxyFunc(o Options) (func(*http.Request) (*url.URL, error), error) {
	if o.ProxyURL == nil {
		return http.ProxyFromEnvironment, nil
	}
	if (o.ProxyURL.Scheme != "http" && o.ProxyURL.Scheme != "https") || o.ProxyURL.Host == "" {
		return nil, fmt.Errorf("registry: proxy URL %q must be http(s)://host[:port]", RedactURL(o.ProxyURL))
	}
	p := *o.ProxyURL
	if o.ProxyUser != "" || o.ProxyPassword != "" {
		p.User = url.UserPassword(o.ProxyUser, o.ProxyPassword)
	}
	proxy := p.String()
	f := (&httpproxy.Config{HTTPProxy: proxy, HTTPSProxy: proxy, NoProxy: strings.Join(o.NoProxy, ",")}).ProxyFunc()
	return func(r *http.Request) (*url.URL, error) { return f(r.URL) }, nil
}

// RedactURL returns u without userinfo, for errors and logs.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	return c.String()
}
