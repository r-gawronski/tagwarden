# Release

`.github/workflows/build.yaml` builds the operator image and the Helm chart.

## What is built

- Image: the `Dockerfile`, built with docker buildx for `linux/amd64` and
  `linux/arm64`. The builder stage cross-compiles on the runner platform, so
  no emulation runs. The binary is built with `-trimpath` and
  `-ldflags "-s -w -X main.version=<version>"`. The base is
  `gcr.io/distroless/static:nonroot` and the builder is `golang:1.26`, both
  pinned by digest and bumped by Dependabot. Release builds set
  `SOURCE_DATE_EPOCH` to the commit time. Builds are not verified to be
  bit-for-bit reproducible.
- Chart: `make chart-package` copies `dist/chart`, sets `version` and
  `appVersion` to the release version and the default
  `manager.image.repository` to `ghcr.io/<owner>/tagwarden`, then packages
  and lints it. The committed chart keeps its placeholder repository.

ko was not used: ko puts the binary at `/ko-app/<name>`, while the manager
Deployment runs `/manager`. The Dockerfile also stays the single build
definition for `make docker-build` and the e2e tests.

## Where it goes

| Trigger | Result |
|---------|--------|
| Pull request | Both platforms built, not pushed. Trivy scans the `linux/amd64` image and fails on fixed CRITICAL or HIGH findings. The release chart is packaged and linted with version `0.0.0-ci.<shortsha>`. |
| Push to `main` | Image `ghcr.io/<owner>/tagwarden:main-<shortsha>`, scanned per platform, signed, with an SBOM attestation per platform. |
| Tag `v<semver>` (pushed, or dispatched by the Release workflow) | Image `ghcr.io/<owner>/tagwarden:<version>` as for `main`, and chart `oci://ghcr.io/<owner>/charts/tagwarden:<version>`, signed. Then a GitHub Release for the tag (see below). |

`<owner>` is the lowercased repository owner and `<version>` is the tag
without the leading `v`. The job fails for a tag that is not strict
`v<major>.<minor>.<patch>[-<pre-release>]` semver, or that points at a commit
not on `main`.

Only the `publish` job can write packages and request an OIDC token. It runs
after the build, scan and chart jobs pass. After the push, Trivy scans each
platform image of the pushed index (CRITICAL and HIGH, fixed only). A finding
stops the job before anything is signed.

GHCR packages start private. After the first push, the maintainer makes the
image and chart packages public once.

## Cutting a release

Run the **Release** workflow (`.github/workflows/release.yaml`) from the
Actions tab on `main`, or from a terminal:

```sh
gh workflow run release.yaml --ref main -f version=0.1.0-rc.1
```

`version` is strict semver without the leading `v`. The workflow refuses to
run off `main`, refuses a version whose tag exists, creates the annotated tag
`v<version>` on the `main` commit it runs on, and dispatches `build.yaml` on
that tag. Only that dispatch publishes; a dispatch of `build.yaml` on a branch
fails.

Tags created with `GITHUB_TOKEN` do not trigger `push` workflows, which is why
the Release workflow dispatches `build.yaml` explicitly (`workflow_dispatch`
is allowed from `GITHUB_TOKEN`). The signing identity stays
`build.yaml@refs/tags/v<version>`. An admin can still push a `v*` tag by hand;
that triggers `build.yaml` through `push`.

The `release tags` ruleset blocks moving and deleting `v*` tags; only
repository admins can bypass it. Creating a tag is not restricted by the
ruleset, because a personal repository cannot list the GitHub Actions app as
a bypass actor. Creating one still needs write access: a collaborator with
write, or a workflow on `main` with `contents: write`. Fork pull requests get
a read-only token, and the default workflow token is read-only.

## GitHub Release

For a `v*` tag, the `release` job runs after `publish` succeeds, that is
after the scan, signing and verification. It is the only job with
`contents: write`. It runs
`gh release create <tag> --verify-tag --generate-notes`, with `--prerelease`
when the version has a pre-release suffix (`v0.1.0-rc.1`).

Attached files: the packaged chart `tagwarden-<version>.tgz` and one SPDX SBOM
per platform, `tagwarden_<version>_linux_<arch>.spdx.json`. `publish` hands
them over as a workflow artifact. The notes start with the image and chart
references with digests and a `cosign verify` example, followed by the
generated changelog. `.github/release.yml` groups the changelog by label
(security, enhancement, bug, documentation, ci/dependencies/test) and skips
PRs labelled `skip-changelog`.

## Signatures and SBOM

Signing is keyless: cosign uses the workflow's GitHub OIDC token, Fulcio
issues a short-lived certificate and Rekor records the signature. Images and
charts are signed by digest, never by tag. `cosign sign --recursive` signs
the image index and each platform image. syft generates an SPDX JSON SBOM for
each platform image, and `cosign attest --type spdxjson` attaches it to that
platform digest. The workflow verifies every signature and attestation
against its exact identity (`build.yaml@<ref>`) before it ends.

Keyless signing writes the repository name, workflow path and ref to the
public Rekor transparency log.

Verify a release:

```sh
IDENTITY='^https://github\.com/<owner>/tagwarden/\.github/workflows/build\.yaml@refs/tags/v.+$'
ISSUER=https://token.actions.githubusercontent.com

cosign verify ghcr.io/<owner>/tagwarden:<version> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

# SBOMs are attached to the platform images. List their digests:
docker buildx imagetools inspect ghcr.io/<owner>/tagwarden:<version>
cosign verify-attestation --type spdxjson ghcr.io/<owner>/tagwarden@<platform-digest> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

cosign verify ghcr.io/<owner>/charts/tagwarden:<version> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

For `main` images, use `@refs/heads/main$` at the end of the identity. Pin
the digest that `cosign verify` reports when you deploy.

## Later

Phase 6 adds goreleaser and SLSA L3 provenance.
