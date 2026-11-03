# CLAUDE.md

Tagwarden is a Kubernetes operator (Go, kubebuilder v4) that mirrors selected container images and Helm charts into an OCI registry. It targets air-gapped, regulated environments: the only internet path is an HTTP(S) proxy, and every mirrored artifact must be verified and traceable.

Kubebuilder layout, generated files and scaffold rules: @AGENTS.md

## Hard rules

- **Open source from day one.** No personal names, company, customer or industry names, homelab hostnames or internal domains in code, docs, tests, CRD groups, image names or commit messages. Use `example.internal` / `example.com` in examples.
- **API group is `mirror.tagwarden.dev`.** Do not add groups or rename without an explicit decision; CRD group changes break users.
- **Security first.** Never add `InsecureSkipVerify`, disabled signature checks or plaintext credentials as defaults. Secrets come only from Secret references and must never appear in status, Events, logs or errors (test for it).
- **Least privilege.** Sync Jobs get no ServiceAccount token, run distroless nonroot with read-only root FS, drop ALL capabilities, seccomp RuntimeDefault. Controller RBAC only for what reconcile needs; RBAC markers are the source of truth.
- **Digest first.** Resolve a tag to a digest once, copy by digest, then tag. Never trust a tag twice.
- **No new dependency** when the standard library or an existing one (go-containerregistry, sigstore, Masterminds/semver, controller-runtime) covers it.

## Workflow

- TDD: failing test first, then the minimal code. Table tests for pure logic, envtest for controllers, in-process registries (`go-containerregistry/pkg/registry`) for sync, kind for e2e.
- Before every commit: `make manifests generate fmt vet lint test` and `govulncheck ./...`. Generated files are committed.
- Conventional commits (`feat(scope):`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`), one logical change per commit, DCO sign-off (`git commit -s`). No AI attribution trailers.
- GitHub Actions: pin every action by full commit SHA, `permissions: {contents: read}` by default.
- Plan and design docs live in `docs/design/`; threat model in `docs/threat-model.md`. Update the threat model when a change touches trust boundaries (network, credentials, signatures).
- Prose: plain ASCII, short sentences, no filler.

## Layout additions (beyond kubebuilder)

```
internal/tags/      Tag selection (regex include/exclude, semver range, keep latest N)
internal/registry/  HTTP transport: proxy, custom CA, mTLS
internal/sync/      Copy engine used by the `sync` subcommand
internal/vuln/      Trivy report parsing, exceptions and verdicts for the vulnerability gate
cmd/main.go         Subcommands: manager (default), sync
```
