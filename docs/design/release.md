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
| Tag `v<semver>` | Image `ghcr.io/<owner>/tagwarden:<version>` as for `main`, and chart `oci://ghcr.io/<owner>/charts/tagwarden:<version>`, signed. |

`<owner>` is the lowercased repository owner and `<version>` is the tag
without the leading `v`. The job fails for a tag that is not strict
`v<major>.<minor>.<patch>[-<pre-release>]` semver, or that points at a commit
not on `main`.

Only the `publish` job can write packages and request an OIDC token. It runs
after the build, scan and chart jobs pass. After the push, Trivy scans each
platform image of the pushed index (CRITICAL and HIGH, fixed only). A finding
stops the job before anything is signed.

GHCR packages of a private repository are private by default. Pulling them
needs a token with `read:packages` until the packages are made public.

Tag protection is missing while the repository is private. When it goes
public, add a tag ruleset for `v*` that limits who can create, move or delete
release tags.

## Signatures and SBOM

Signing is keyless: cosign uses the workflow's GitHub OIDC token, Fulcio
issues a short-lived certificate and Rekor records the signature. Images and
charts are signed by digest, never by tag. `cosign sign --recursive` signs
the image index and each platform image. syft generates an SPDX JSON SBOM for
each platform image, and `cosign attest --type spdxjson` attaches it to that
platform digest. The workflow verifies every signature and attestation
against its exact identity (`build.yaml@<ref>`) before it ends.

Keyless signing writes the repository name, workflow path and ref to the
public Rekor transparency log, even while the repository is private.

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
