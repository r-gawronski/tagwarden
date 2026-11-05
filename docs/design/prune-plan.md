# Prune Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Delete target tags a mirror no longer selects (`spec.tags.prune`), starting with Harbor tag delete (#71) that both Untag and prune need.

**Architecture:** PR 1 adds `ClusterMirrorTarget.spec.registryFlavor: Harbor`. The controller copies it into the Job spec, `synccmd` builds a Harbor API tag deleter from the target transport and credentials, and `sync` uses it through one `deleteTag` method. PR 2 adds the `status.owned` record, the shared hold rules and the prune step in the Job, per `docs/design/prune.md`.

**Tech Stack:** Go, kubebuilder v4, controller-runtime, go-containerregistry, envtest, `net/http/httptest`.

Rules for every task (CLAUDE.md): TDD, plain ASCII, no homelab names, before each commit `make manifests generate fmt vet lint test` and `govulncheck ./...`, commits `git commit -s`, conventional prefix, no AI trailers.

---

## PR 1: Harbor tag delete (#71), branch `feat/71-harbor-tag-delete`

### Task 1: Harbor tag deleter

**Files:**
- Create: `internal/registry/harbor.go`
- Test: `internal/registry/harbor_test.go`

**Step 1: Write the failing test**

```go
package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestHarborDeleteTag(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name   string
		status int
		want   error // nil, ErrTagNotFound or errAny
	}{
		{name: "deleted", status: http.StatusOK},
		{name: "tag not on digest", status: http.StatusNotFound, want: ErrTagNotFound},
		{name: "forbidden", status: http.StatusForbidden, want: errAny},
		{name: "redirect is not followed", status: http.StatusFound, want: errAny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotUser, gotPass, gotMethod string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.EscapedPath()
				gotUser, gotPass, _ = r.BasicAuth()
				if tc.status == http.StatusFound {
					http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("server text password=hunter2"))
			}))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "https://")
			repo, err := name.NewRepository(host + "/mirror/docker.io/library/nginx")
			if err != nil {
				t.Fatal(err)
			}
			del := HarborDeleteTag(srv.Client().Transport, authn.FromConfig(authn.AuthConfig{Username: "robot$push", Password: "s3cret"}), repo)

			err = del(context.Background(), "1.31.8", digest)

			switch {
			case tc.want == nil && err != nil, tc.want == ErrTagNotFound && !errors.Is(err, ErrTagNotFound), tc.want == errAny && err == nil:
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if err != nil && (strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "hunter2")) {
				t.Fatalf("error leaks credentials or server text: %v", err)
			}
			want := "/api/v2.0/projects/mirror/repositories/docker.io%252Flibrary%252Fnginx/artifacts/" + digest + "/tags/1.31.8"
			if gotMethod != http.MethodDelete || gotPath != want || gotUser != "robot$push" || gotPass != "s3cret" {
				t.Fatalf("got %s %s as %q", gotMethod, gotPath, gotUser)
			}
		})
	}
}

var errAny = errors.New("any error")
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/ -run TestHarborDeleteTag`
Expected: FAIL, `undefined: HarborDeleteTag`.

**Step 3: Write minimal implementation**

```go
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

// ErrTagNotFound means the registry has no such tag on the digest: it was
// deleted already or moved to another digest.
var ErrTagNotFound = errors.New("harbor: not found")

// HarborDeleteTag returns a function that deletes a tag from one digest of
// repo through the Harbor API. Harbor refuses tag DELETE on /v2. The call
// is scoped to the digest, so a tag that moved is never deleted. Errors
// carry the HTTP status only, never server text or credentials, and
// redirects are not followed, so credentials go to the target host only.
func HarborDeleteTag(rt http.RoundTripper, auth authn.Authenticator, repo name.Repository) func(ctx context.Context, tag, digest string) error {
	c := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	project, path, _ := strings.Cut(repo.RepositoryStr(), "/")
	return func(ctx context.Context, tag, digest string) error {
		if path == "" {
			return errors.New("harbor: repository has no path below the project")
		}
		a, err := auth.Authorization()
		if err != nil || a.Username == "" || a.Password == "" {
			return errors.New("harbor: tag delete needs a username and password")
		}
		// Harbor wants the repository name URL-encoded twice.
		u := fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/tags/%s",
			repo.Scheme(), repo.RegistryStr(), url.PathEscape(project), url.PathEscape(url.PathEscape(path)), digest, url.PathEscape(tag))
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return errors.New("harbor: invalid tag delete request")
		}
		req.SetBasicAuth(a.Username, a.Password)
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("harbor: delete tag: %w", Redact(err))
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
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
```

`Redact` stands for the existing userinfo redaction helper in `internal/registry/transport.go` (T8). Check its real name with `grep -n "func .*[Rr]edact" internal/registry/*.go` and use it; if there is none, return `errors.New("harbor: delete tag: request failed")` instead of wrapping.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/registry/ -run TestHarborDeleteTag -v`
Expected: PASS, 4 subtests.

**Step 5: Commit**

```bash
git add internal/registry/harbor.go internal/registry/harbor_test.go
git commit -s -m "feat(registry): delete a tag from a digest through the Harbor API (#71)"
```

### Task 2: One tag delete path in sync, Untag uses it

**Files:**
- Modify: `internal/sync/sync.go:60-77` (Request), add `deleteTag` method next to `newSyncer` (~line 228)
- Modify: `internal/sync/rescan.go:106-128` (`untag`)
- Test: `internal/sync/rescan_test.go`

**Step 1: Write the failing test**

Add two rows to the `TestRescan` table and a `deleteTag` field:

```go
deleter func(ctx context.Context, tag, digest string) error
```

```go
{name: "untag uses the target deleter", untag: true, untaggable: []string{v100}, noDelete: true,
	deleter: deleteVia(&dst), want: v1alpha1.VulnerableUntagged, gone: true},
{name: "untag refuses a tag the deleter does not find", untag: true, untaggable: []string{v100},
	deleter: func(context.Context, string, string) error { return registry.ErrTagNotFound }, want: v1alpha1.VulnerableUntagRefused},
```

and set `req.DeleteTag = tc.deleter` before `Rescan`. `deleteVia` is a test helper that deletes the tag on the in-process registry directly (bypassing `noDelete`) after checking the digest, so the row proves the deleter is used instead of `/v2` tag delete. Write it next to `newRegistry` in the sync test helpers; it needs `remote.Delete` with a `remote.WithTransport` that skips the `noDelete` hook. Read `newRegistry` and `regOpts` first and follow how `noDelete` is wired.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/sync/ -run TestRescan`
Expected: FAIL to compile, `unknown field DeleteTag`.

**Step 3: Write minimal implementation**

In `Request`:

```go
	// DeleteTag deletes a target tag from one digest. Nil uses the OCI
	// distribution tag delete. synccmd sets it for registries that refuse
	// that, such as Harbor; it returns registry.ErrTagNotFound when the tag
	// is not on the digest.
	DeleteTag func(ctx context.Context, tag, digest string) error
```

In `sync.go`:

```go
// deleteTag deletes tag, which the caller resolved to digest, from the
// target.
func (s *syncer) deleteTag(ctx context.Context, tag, digest string) error {
	if s.req.DeleteTag != nil {
		return s.req.DeleteTag(ctx, tag, digest)
	}
	return s.pusher.Delete(ctx, s.req.Target.Tag(tag))
}
```

In `untag`, replace the `s.pusher.Delete` block:

```go
	if err := s.deleteTag(ctx, a.Tag, a.Digest); errors.Is(err, registry.ErrTagNotFound) {
		return v1alpha1.VulnerableUntagRefused
	} else if err != nil {
		res.Errors = append(res.Errors, a.Tag+": untag failed, kept: "+short(err))
		return v1alpha1.VulnerableUntagFailed
	}
	return v1alpha1.VulnerableUntagged
```

Also fix the `Result` comment at `sync.go:100-103` only if it still says "prune ... phase 4" in a way that is wrong after PR 2; leave it in PR 1.

**Step 4: Run tests**

Run: `go test ./internal/sync/`
Expected: PASS, all old rows unchanged.

**Step 5: Commit**

```bash
git add internal/sync/
git commit -s -m "feat(sync): delete tags through a target deleter when one is set (#71)"
```

### Task 3: Job spec field `targetFlavor`

**Files:**
- Modify: `internal/syncspec/spec.go:261-299` (Spec), validation loop at `:363`
- Test: `internal/syncspec/spec_test.go`

**Step 1: Write the failing test**

Add table rows to the existing validation test (find it with `grep -n "func Test" internal/syncspec/spec_test.go`):

- `targetFlavor: "Harbor"` with dockerconfigjson auth: valid.
- `targetFlavor: "Quay"`: error `unknown targetFlavor "Quay"`.
- `targetFlavor: "Harbor"` with `targetAuth: AuthAzureWorkloadIdentity` (and `azure` set): error `targetFlavor Harbor: needs the target Secret credentials`.

**Step 2: Run test, expect FAIL** (`go test ./internal/syncspec/`).

**Step 3: Implement**

```go
// FlavorHarbor is Spec.TargetFlavor for Harbor: tags are deleted through
// the Harbor API.
const FlavorHarbor = "Harbor"
```

Field in `Spec`, after `SourceAuth`:

```go
	// TargetFlavor is the target's registryFlavor. Empty means OCI
	// distribution.
	TargetFlavor string `json:"targetFlavor,omitempty"`
```

Validation, after the auth loop:

```go
	switch s.TargetFlavor {
	case "":
	case FlavorHarbor:
		if s.TargetAuth != "" {
			return errors.New("targetFlavor Harbor: needs the target Secret credentials")
		}
	default:
		return fmt.Errorf("unknown targetFlavor %q", s.TargetFlavor)
	}
```

**Step 4: Run tests, expect PASS.**

**Step 5: Commit** `feat(syncspec): carry the target registry flavor (#71)`.

### Task 4: `ClusterMirrorTarget.spec.registryFlavor` and rendering

**Files:**
- Modify: `api/v1alpha1/clustermirrortarget_types.go:614-631`
- Modify: `internal/controller/render.go:242`
- Test: `internal/controller/validation_test.go` (CEL), `internal/controller/render_golden_test.go` or the nearest render unit test
- Regenerate: `make manifests generate helm`

**Step 1: Write the failing tests**

- CEL (envtest, follow the existing table in `validation_test.go`): a target with `registryFlavor: Harbor` and `auth.azureWorkloadIdentity` is rejected with `registryFlavor Harbor needs credentialsSecretRef`; with `credentialsSecretRef` it is accepted; `registryFlavor: Quay` is rejected by the enum.
- Render: a target with `registryFlavor: Harbor` renders a ConfigMap spec with `"targetFlavor":"Harbor"`. The existing golden test (no flavor) must stay byte for byte unchanged.

**Step 2: Run, expect FAIL** (`make test` or `go test ./internal/controller/ -run 'Validation|Render'` with envtest assets set up by `make setup-envtest`).

**Step 3: Implement**

Types:

```go
// RegistryFlavor names a registry that needs its own API for an operation
// OCI distribution does not offer.
// +kubebuilder:validation:Enum=Harbor
type RegistryFlavor string

// RegistryFlavorHarbor deletes tags through the Harbor API.
const RegistryFlavorHarbor RegistryFlavor = "Harbor"
```

Field in `ClusterMirrorTargetSpec`, after `Auth`:

```go
	// registryFlavor turns on registry-specific calls. Harbor deletes tags
	// (Untag, prune) through the Harbor API, because Harbor refuses tag
	// delete on /v2; the credentials then need Harbor's delete tag
	// permission. Empty means OCI distribution.
	// +optional
	RegistryFlavor RegistryFlavor `json:"registryFlavor,omitempty"`
```

CEL marker on `ClusterMirrorTargetSpec`, with the others at `:615-621`:

```go
// +kubebuilder:validation:XValidation:rule="!has(self.registryFlavor) || has(self.credentialsSecretRef)",message="registryFlavor Harbor needs credentialsSecretRef"
```

Render, after `s.TargetAuth, s.SourceAuth = cloudAuth(t, m)`:

```go
	s.TargetFlavor = string(t.Spec.RegistryFlavor)
```

Then `make manifests generate helm`.

**Step 4: Run** `make test`, expect PASS.

**Step 5: Commit** `feat(api): registryFlavor on ClusterMirrorTarget (#71)` with the generated CRDs, deepcopy and chart CRD.

### Task 5: Wire the Harbor deleter in synccmd

**Files:**
- Modify: `internal/synccmd/synccmd.go:220-234` (the `sync.Request` literal)
- Test: `internal/synccmd/synccmd_test.go` (find the test that builds a Request from a spec)

**Step 1: Failing test:** a spec with `TargetFlavor: syncspec.FlavorHarbor` gives a Request with `DeleteTag != nil`; without it, `DeleteTag == nil`.

**Step 2: Run, expect FAIL.**

**Step 3: Implement** after the literal is built (assign it to `req` first):

```go
	if spec.TargetFlavor == syncspec.FlavorHarbor {
		req.DeleteTag = registry.HarborDeleteTag(dstT, auth, spec.TargetRepo)
	}
```

`dstT` is the target transport with CA, client certificate and proxy, so the Harbor call takes the same network path as pushes.

**Step 4: Run** `go test ./internal/synccmd/`, expect PASS.

**Step 5: Commit** `feat(synccmd): use the Harbor tag deleter for Harbor targets (#71)`.

### Task 6: Docs and threat model for PR 1

**Files:**
- Modify: `docs/install.md:778-783` (section 7, Harbor): set `registryFlavor: Harbor`, robot permission "delete tag" on the mirror projects, Untag now works.
- Modify: `docs/install.md:770-776`: Untag needs delete rights; on Harbor that is the Harbor API call.
- Modify: `config/samples/mirror_v1alpha1_clustermirrortarget.yaml`: commented `# registryFlavor: Harbor`.
- Modify: `docs/threat-model.md` T13: the race note now says the Harbor path is digest-scoped and closes it; T8: the Harbor call sends basic auth only to the target host and never follows redirects.
- Modify: `docs/design/vulnerability-gate.md:1183-1184,1199`: drop "follow-up #71" notes, point to `registryFlavor`.
- Modify: `CHANGELOG.md` unreleased section, if the repo keeps one (`make changelog` moves commits at release; check `docs/design/release.md`).

**Commit** `docs: Harbor tag delete with registryFlavor (#71)`.

### Task 7: Verify and open PR 1

- `make manifests generate fmt vet lint test`, `govulncheck ./...`, `make chart-check`.
- Push `feat/71-harbor-tag-delete`, open PR "feat: Harbor tag delete through the Harbor API (#71)", body `Closes #71`.
- Manual check after merge and deploy: set `registryFlavor: Harbor` on the target, run a re-scan with Untag on a test project, confirm the tag goes and other tags of the digest stay (acceptance of #71).

---

## PR 2: prune, branch `feat/prune` (rebased on PR 1)

Detailed steps are written after PR 1 merges, because they build on its `deleteTag`. The task list and files are fixed now:

1. **API** (`api/v1alpha1/artifactmirror_types.go`): `TagSelector.Prune bool` (`prune`, optional, default false); `ArtifactMirrorStatus.Owned []SyncedTag` (`owned`, MaxItems 200, `listType=atomic`). `make manifests generate helm`. Commit `feat(api): prune and status.owned`.
2. **Owned merge** (`internal/controller/status.go` near `:220-230`): pure function `mergeOwned(owned, synced, pruned, missing []SyncedTag) (out []SyncedTag, truncated bool)`, table tests first: merge by tag, run digest wins, drop pruned and missing, cap 200 dropping the lowest versions. Called next to the `status.synced` update for non-rescan reports only. Commit `feat(controller): record owned tags`.
3. **Shared hold rules** (`internal/controller/gate.go:99-140`): extract `heldTags(ctx, t, m) (held map[string]bool, all bool, err error)` from `untaggable`, make `untaggable` use it (existing tests unchanged), table tests for the new function. Commit `refactor(controller): share the T13 hold rules`.
4. **Job spec** (`internal/syncspec/spec.go`): `Prunable []SyncedTag` (`prunable`, omitempty), validated like `untaggable` (valid tags and digests, at most 200). Render it in `internal/controller/render.go` only when `prune` is on and the mirror is allowed; candidates = `owned` minus `heldTags`; empty when `all`. Golden test unchanged without prune. Commit `feat(controller): pass prunable tags to the Job`.
5. **Prune step** (`internal/sync/sync.go`, new `internal/sync/prune.go`): after copies in `Run`, for each prunable tag not in `Result.Selected`: resolve on target, skip and report missing if gone, keep if digest differs, else `s.deleteTag`. Skip the whole step when listing failed, `len(Selected) == 0`, any `Failed`, or a refused mutation. Results in `Result.Pruned` and `Result.Missing`; failed deletes as `"<tag>: prune failed, kept: ..."` in `Errors`, exit code unchanged. Tests on the in-process registry for every case in the design. Commit `feat(sync): prune tags the mirror no longer selects`.
6. **Report and status** (`internal/syncspec` report types, `internal/controller/status.go`): `pruned` in the termination message; a pruned tag outside the sent `prunable` makes the report `Crashed` (T12 test); `pruned N` in the Synced summary; `TagPruned` Events capped like the gate Events. Commit `feat(controller): report pruned tags`.
7. **Docs**: README `prune: true` example, `docs/install.md` (opt-in, Harbor GC on untagged artifacts, no backfill), sample, threat model T13 phase 4 done, remove the phase 4 note in the `Result` comment and `docs/design/auto-mirror.md:100` if it still applies. Commit `docs: prune`.
8. **Verify and PR**: full make targets, `govulncheck`, push, PR "feat: prune tags a mirror no longer selects".
