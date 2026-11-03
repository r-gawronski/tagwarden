# Release

`.github/workflows/build.yaml` builds the operator image and the Helm chart.

## What is built

- Image: the `Dockerfile`, built with docker buildx for `linux/amd64` and
  `linux/arm64`. The builder stage cross-compiles on the runner platform, so
  no emulation runs. The binary is built with `-trimpath` and
  `-ldflags "-s -w -X main.version=<version>"`. The base is
  `gcr.io/distroless/static:nonroot`, pinned by digest. Release builds set
  `SOURCE_DATE_EPOCH` to the commit time.
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
| Push to `main` | Image `ghcr.io/<owner>/tagwarden:main-<shortsha>`, signed, with an SBOM attestation. |
| Tag `v<semver>` | Image `ghcr.io/<owner>/tagwarden:<version>` and chart `oci://ghcr.io/<owner>/charts/tagwarden:<version>`, both signed. The image has an SBOM attestation. |

`<owner>` is the lowercased repository owner and `<version>` is the tag
without the leading `v`. Tags that are not `v<major>.<minor>.<patch>` with an
optional pre-release fail the job.

Only the `publish` job can write packages and request an OIDC token. It runs
after the build, scan and chart jobs pass.

## Signatures and SBOM

Signing is keyless: cosign uses the workflow's GitHub OIDC token, Fulcio
issues a short-lived certificate and Rekor records the signature. Images and
charts are signed by digest, never by tag. syft generates an SPDX JSON SBOM
of the image (the `linux/amd64` variant of the index), and
`cosign attest --type spdxjson` attaches it to the image digest. The
workflow verifies every signature and the attestation before it ends.

Verify a release:

```sh
IDENTITY='^https://github\.com/<owner>/tagwarden/\.github/workflows/build\.yaml@refs/tags/v.+$'
ISSUER=https://token.actions.githubusercontent.com

cosign verify ghcr.io/<owner>/tagwarden:<version> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

cosign verify-attestation --type spdxjson ghcr.io/<owner>/tagwarden:<version> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

cosign verify ghcr.io/<owner>/charts/tagwarden:<version> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

For `main` images, use `@refs/heads/main$` at the end of the identity. Pin
the digest that `cosign verify` reports when you deploy.

## Later

Phase 6 adds goreleaser and SLSA L3 provenance.
