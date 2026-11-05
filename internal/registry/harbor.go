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

package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// ErrTagNotFound means Harbor answered 404: the tag, artifact, repository
// or project was not found.
var ErrTagNotFound = errors.New("harbor: not found")

// HarborDeleteTag returns a function that removes one tag from one digest
// through the Harbor API. Harbor refuses the OCI tag delete
// (DELETE /v2/<repo>/manifests/<tag>), so this uses
// DELETE /api/v2.0/projects/{project}/repositories/{path}/artifacts/{digest}/tags/{tag}.
// The first segment of repo is the Harbor project, the rest the repository.
func HarborDeleteTag(rt http.RoundTripper, auth authn.Authenticator, repo name.Repository) func(ctx context.Context, tag, digest string) error {
	client := &http.Client{
		Transport: rt,
		// Never follow a redirect: credentials go only to the target host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context, tag, digest string) error {
		project, path, _ := strings.Cut(repo.RepositoryStr(), "/")
		if path == "" {
			return fmt.Errorf("harbor: repository %q has no path after the project", repo.RepositoryStr())
		}
		cfg, err := authn.Authorization(ctx, auth)
		if err != nil {
			return errors.New("harbor: delete tag: cannot read credentials")
		}
		if cfg.Username == "" || cfg.Password == "" {
			return errors.New("harbor: delete tag: username and password are required")
		}
		// Harbor wants the repository path escaped twice ("/" -> "%252F").
		u := fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/tags/%s",
			repo.Scheme(), repo.RegistryStr(), url.PathEscape(project),
			url.PathEscape(url.PathEscape(path)), url.PathEscape(digest), url.PathEscape(tag))
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return fmt.Errorf("harbor: delete tag: %w", err)
		}
		req.SetBasicAuth(cfg.Username, cfg.Password)
		resp, err := client.Do(req)
		if err != nil {
			// Safe to wrap: credentials are in the Authorization header, never
			// in the URL, so the *url.Error carries no secret.
			return fmt.Errorf("harbor: delete tag: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return nil
		case http.StatusNotFound:
			return ErrTagNotFound
		default:
			return fmt.Errorf("harbor: delete tag: HTTP %d", resp.StatusCode)
		}
	}
}
