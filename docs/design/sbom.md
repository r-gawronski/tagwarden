# SBOM generation and enforcement for mirrored images

Status: Proposed. Issue #69. Builds on the vulnerability gate (#21,
`docs/design/vulnerability-gate.md`) and reuses its Trivy sidecar.

## Goal

Every image that Tagwarden mirrors into a target can carry an SBOM, so that
consumers and audits see what is inside without pulling the image. The
platform team sets the policy on the `ClusterMirrorTarget`. Tenants create
`ArtifactMirror` objects and cannot turn it off or weaken it.

Today Tagwarden copies upstream referrers when they exist. Most upstream
images publish no SBOM, and nothing makes one mandatory.

What the platform team can choose per target:

| Mode | Behaviour |
|------|-----------|
| `Disabled` (default) | As today. Upstream SBOM referrers are copied like any referrer. |
| `PreferUpstream` | Use a valid upstream SBOM referrer of the configured format when the platform child has one. Generate one otherwise. |
| `Generate` | Always attach a Tagwarden-generated SBOM. Upstream SBOMs are still copied, but they do not count. |

With `required: true` the policy fails closed: a new tag whose SBOM cannot
be produced or attached for every platform child is not published.

Out of scope:

- Admission-time enforcement in consuming clusters. That stays with Kyverno
  or Sigstore policy-controller, which require a signed SBOM attestation
  from the platform key. The docs show example policies (step 8).
- Helm charts (`HelmOCI`, `HelmRepo`). Trivy has no meaningful SBOM for a
  chart. The policy applies to `Image` mirrors only, and chart mirrors on
  the same target are not affected.
- Keyless signing. It needs online Fulcio and Rekor, which air-gapped
  targets do not have.
- Licence or policy evaluation of SBOM content. Tagwarden produces and
  attaches SBOMs; it does not judge them.
- Rewriting or merging upstream SBOMs.

## Constraints

From CLAUDE.md, the threat model and the gate design:

- Digest first. The mirrored manifest stays digest-identical to upstream.
  An SBOM is a separate manifest that refers to it (OCI 1.1 `subject`).
- Sync Jobs run distroless nonroot, read-only root FS, no ServiceAccount
  token. The generator holds no registry Secrets and no proxy credentials.
- The source transport enforces the T16 checks. The generator never talks
  to a registry or the internet.
- No new Go dependency. go-containerregistry already writes OCI 1.1
  referrers and the referrers tag fallback.
- The termination message is capped at 4096 bytes and is untrusted input
  for the controller (T12).
- Policy lives on the target only. No field on `ArtifactMirror`.

## Facts that shape the design

Read on 2026-11-04. Rows marked "spike" are checked in step 0.

| Item | Value |
|------|-------|
| Trivy SBOM output | `trivy image --format cyclonedx` or `--format spdx-json`, same `--input <layout>@sha256:<digest>` input as the gate. With an SBOM format Trivy does not run the vulnerability scanner unless `--scanners vuln` is given. |
| Vulnerability DB for SBOM | Not needed: SBOM output lists packages, it does not match them. No `--server`, no DB download (spike: confirm with `--skip-db-update --offline-scan` and no network). |
| Java DB for SBOM | The JAR analyzer looks up artifacts without `pom.properties` in the Java DB. In the gate spike the client exited FATAL on any JAR without a Java DB. Spike: confirm for SBOM output; same two modes as the gate either way. |
| SBOM size | Spike: CycloneDX and SPDX size for the gate spike images (Alpine, nginx, tomcat, the large Python image). |
| OCI 1.1 referrer | An image manifest with `subject` set to the described manifest, `artifactType` set to the SBOM media type, the empty config `application/vnd.oci.empty.v1+json` (`{}`, 2 bytes) and one layer with the SBOM. |
| SBOM media types | CycloneDX JSON `application/vnd.cyclonedx+json`, SPDX JSON `application/spdx+json`. Both are already in the gate's referrer allowlist (`vuln.SupplyChainArtifact`). |
| Registries without the referrers API | OCI distribution spec 1.1 defines the referrers tag schema: an image index tagged `sha256-<hex>` that lists the referrers. go-containerregistry `remote.Write` detects a missing `OCI-Subject` response header and updates that index itself, with `artifactType` and annotations of the referrer. `remote.Referrers` reads it back. |
| cosign `.sbom` tag | `sha256-<hex>.sbom`, cosign's legacy single-artifact scheme. Upstream images use it; Tagwarden copies it (sync engine) but never writes it. |
| buildkit SBOM attestations | In-toto attestation manifests inside the image index (`vnd.docker.reference.type: attestation-manifest`). Copied with the index as today. |
| Referrers API support | Spike: distribution (registry:3), zot, Harbor, Quay, Artifactory, ACR, ECR, GAR. Which return `OCI-Subject` and which need the tag fallback. |
| Admission policies | Kyverno `verifyImages.attestations` and policy-controller `ClusterImagePolicy` verify signed in-toto attestations, not unsigned referrers. Unsigned SBOMs help audits and tooling (`oras discover`, `trivy sbom`), not admission. Spike before step 8: attestation formats both accept with a key (cosign `.att` tag, sigstore bundle referrer). |

## Options

### Where to generate

**A. Trivy in the sync pod, from the local OCI layout.** (Recommended.)

- Same model as the gate: the sync container writes the artifact into an
  `emptyDir` layout through its checked transport, a Trivy sidecar reads it
  read-only and writes the SBOM to a file. The sync container validates it
  and pushes it.
- The generator has no registry Secrets and no network need.
- One upstream download per digest, shared with the gate when both are on.
- The SBOM describes exactly the bytes Tagwarden pushes.

**B. syft or another generator.** A second image to pin, mirror and keep
compatible, with no gain over Trivy, whose image the platform already
mirrors for the gate. Rejected for the first version. The sidecar protocol
does not depend on Trivy, so another generator can be added later.

**C. Generate from the target after the push.** The tag would have to be
published before its SBOM exists, or the digest sit untagged while the
generator pulls it with target read credentials. Rejected: it breaks
fail-closed and puts credentials in the generator.

**D. Trivy as a Go library.** Rejected for the reasons in the gate design
(option B there).

### Where the SBOM lives

**A. OCI 1.1 referrer per platform child.** (Recommended.)

- `subject` is the child digest, so the SBOM is bound to the bytes it
  describes and the mirrored manifest does not change.
- Tooling finds it with the referrers API or the tag fallback.

**B. Add an attestation manifest to the index.** Changes the index digest.
Rejected: digest first.

**C. cosign `.sbom` tag.** One tag per digest, no format or platform in the
name, deprecated by cosign, and it collides with the upstream `.sbom` tag
that the sync engine copies. Rejected.

## Design

### Which Jobs generate

A sync Job generates SBOMs when both hold:

- its target sets `spec.sbom.mode` to `PreferUpstream` or `Generate`, and
- its mirror has `type: Image` (the default).

This covers user-defined and generated mirrors alike. The spec the
controller renders carries the policy from the target; the mirror has no
field for it, and sync now runs the same Job. The CronJob and its spec
ConfigMap live in the operator namespace, and `securityDrift` reverts hand
edits (T11), so a tenant cannot change what the Job does.

Two targets on the same registry and project with different SBOM policies
let tags in through the weaker one. Targets are platform-owned, so this is
a platform configuration error, not a tenant bypass. The controller warns:
a target with `required: true` gets `SBOMReady=False` with reason
`WeakerTargetOnRegistry` and a Warning Event when another target on the
same registry (host compared like the gate's reservation) lists one of its
projects with a weaker policy. Mirrors keep working.

### Policy API

```yaml
spec:
  sbom:
    mode: Generate          # Disabled | PreferUpstream | Generate
    format: CycloneDX       # CycloneDX | SPDX, always JSON
    required: true          # fail closed for new tags
    generator:              # all optional
      image: registry.example.internal/platform/ghcr.io/aquasecurity/trivy@sha256:<digest>
      version: "0.76.1"
      javaDB: Disabled      # Disabled | PerJob
      javaDBRepository: ""  # with PerJob, a path in spec.registry
      timeout: 10m          # per platform child
      storage: 20Gi         # sizeLimit of the work emptyDir
      resources: {}         # sidecar
    signing:                # step 8
      keySecretRef: {name: sbom-signing-key, key: cosign.key}
```

| Field | Default | Notes |
|-------|---------|-------|
| `mode` | `Disabled` | |
| `format` | `CycloneDX` | Enum values follow the API conventions (CamelCase), not the Trivy flag names. Trivy gets `cyclonedx` or `spdx-json`. |
| `required` | `false` | |
| `generator.image`, `version` | manager flags `--trivy-image`, `--trivy-version` | Set together, image pinned by digest (same CEL as `scanner.image`). |
| `generator.javaDB` | `Disabled` | Same meaning and same Java DB fetch as the gate. |
| `generator.timeout` | `10m` | Between 1m and 1h. |
| `generator.storage` | `20Gi` | |
| `generator.resources` | requests 100m/256Mi, limits 2/2Gi | |

CEL:

- `generator.image` and `generator.version` are set together, the image
  pinned by digest.
- `javaDB: PerJob` needs `javaDBRepository`, a path in `spec.registry`.
- `required: true` needs `mode` other than `Disabled`.
- When both `generator.image` and `autoMirror.vulnerabilityGate.scanner.image`
  are set, they are equal. A gated Job runs one sidecar for both (see
  [Sync pod](#sync-pod)), and the scanner image is version-checked against
  the server.

The chart passes `--trivy-image` and `--trivy-version` whenever
`trivy.image.digest` is set, not only with `trivy.enabled`, so SBOMs work
without the in-chart server. `--trivy-url` stays tied to `trivy.enabled`.

### Missing generator configuration

Same rule as the gate: a policy that is on but cannot run must be loud.
When `mode` is not `Disabled` and there is no generator image and version
(neither on the target nor from the manager flags):

- The target gets `SBOMReady=False` with reason `NotConfigured` and a
  Warning Event when it changes.
- The gauge `tagwarden_sbom_not_configured{target="<name>"}` is 1. The
  series is removed when the generator is configured, the mode is
  `Disabled` or the target is deleted.
- With `required: true`, every image mirror of the target gets
  `Ready=False` with reason `SBOMNotConfigured`, an Event and no CronJob.
  Nothing is copied.
- With `required: false`, image mirrors get `SBOM=False` (`NotConfigured`)
  and their Jobs render without the generator. Upstream SBOM referrers are
  still copied.

### Sync pod

The Job of an SBOM mirror renders the gate's layout and scan volumes and a
native sidecar:

- Ungated Job: sidecar `sbom`, the generator image. It gets no Secret, no
  token, no proxy variables and `NO_PROXY=*`. It mounts `work` read-only and
  `scan` read-write. Same security context as `sync`.
- Gated Job (generated mirror with the gate on): the existing `scanner`
  sidecar serves both request kinds. No second Trivy container.
- The `scan` volume keeps its size (64Mi, or 3Gi with `javaDB: PerJob`).
  SBOM files count against it: each file is removed after it is read, so
  64Mi holds the largest single SBOM (see [Size limits](#size-limits)).
- Pods with a generator carry the label `tagwarden.dev/sbom: trivy`.
  NetworkPolicies need no new rule: the generator needs no network.

`syncspec.SidecarScript` gets a second request kind. For each
`req/<hex>.cyclonedx` or `req/<hex>.spdx-json` file it runs

```
trivy image --input "/work/layout@sha256:$h" --format <fixed by suffix> \
  --skip-db-update --skip-java-db-update --offline-scan --skip-version-check \
  --disable-telemetry --timeout "$TAGWARDEN_SBOM_TIMEOUT" \
  --config /dev/null --ignorefile /dev/null "$java" > "out/$h.<suffix>.json"
```

and writes `out/$h.<suffix>.exit`. The format comes from a `case` on the
suffix, never from file content. The hex check, quoting and `/dev/null`
config are the gate's. Without `TAGWARDEN_SCANNER_URL` (ungated Job) the
script ignores `.ready` requests. The sync container reads the output
through the `os.Root` of the scan volume, regular files only, with the cap
from [Size limits](#size-limits). A missing, late, malformed or oversized
answer is a generation failure, never an SBOM.

The scanner start check (`--scanner-start-timeout`) covers the `sbom`
sidecar too: a Job whose generator does not start is deleted with nothing
copied, and `tagwarden_scanner_start_failures_total` counts it.

### Flow of one tag

The gate's flow stays as it is. For a tag of an SBOM mirror:

1. Resolve the tag to a digest (unchanged).
2. Check the target tag, platforms and size (unchanged).
3. Write the artifact into `/work/layout` by digest, as the gate does (one
   top-level descriptor per image child). With the gate on, the same layout
   is scanned first; a blocked tag gets no SBOM and stops here.
4. For each image child (attestation manifests are skipped by the gate's
   content rule), decide the source of its SBOM:
   - `PreferUpstream`: if the source lists a valid upstream SBOM referrer of
     the configured format for the child (see
     [Upstream SBOMs](#upstream-sboms)), use it. It is copied by the
     existing referrer step.
   - Otherwise generate: request `<hex>.<format>`, wait up to
     `generator.timeout` plus 25%, read and check the document.
5. If any child has no SBOM and `required: true`, the tag fails with reason
   `SBOMFailed`: nothing is pushed and the tag does not move. With
   `required: false` the tag goes on and the failure is reported.
6. Push the artifact by digest from the layout (unchanged).
7. Push each generated SBOM as a referrer of its child (see
   [Referrer format](#referrer-format)). For an index, also push each one
   as a referrer of the index (see [Multi-arch indexes](#multi-arch-indexes)).
8. Copy upstream referrers (unchanged). Upstream referrers that carry
   `dev.tagwarden.*` annotations are skipped and listed in
   `skippedReferrers`: only Tagwarden may claim to be Tagwarden.
9. Move the tag. If a referrer push in 7 failed under `required: true`, the
   tag does not move; the digest stays on the target untagged, as for a
   failed referrer copy today, and the next run retries.
10. Delete the layout of this digest before the next tag.

A tag already on the target with the same digest: the Job lists the target
referrers of each child (and of the index) with the SBOM `artifactType`.
If a Tagwarden-generated SBOM of the configured format is there, or under
`PreferUpstream` any valid SBOM of that format, nothing happens. Otherwise
the Job fetches the digest into the layout (from the source, or from the
target with `onTagMutation: Ignore`) and attaches the missing SBOMs. A
published tag is never untagged for a missing SBOM, also under
`required: true`: the tag reports `SBOMMissing` and the mirror
`SBOM=False`. Turning `required` on does not retract tags published before.

The check is a referrers lookup per child and run. That is the same order
of requests as the referrer copy the Job already does for present tags.
Status bookkeeping like the gate's `judged` list is a later optimisation.

### Referrer format

A generated SBOM is pushed as:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.cyclonedx+json",
  "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa3...", "size": 2},
  "layers": [{"mediaType": "application/vnd.cyclonedx+json", "digest": "sha256:...", "size": 123456}],
  "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:<child>", "size": 1234},
  "annotations": {
    "org.opencontainers.image.created": "2026-11-04T12:00:00Z",
    "dev.tagwarden.sbom.generator": "trivy/0.76.1",
    "dev.tagwarden.sbom.java-scanned": "false"
  }
}
```

- The layer is the document as Trivy wrote it. Tagwarden checks it but
  does not rewrite it.
- `dev.tagwarden.sbom.generator` marks a generated SBOM.
  `dev.tagwarden.sbom.java-scanned` is `false` with `javaDB: Disabled`, so
  the JAR blind spot is visible on the artifact itself, as in the gate.
- `dev.tagwarden.sbom.platform` names the platform on the index-level copy.
- On a registry without the referrers API, go-containerregistry updates the
  `sha256-<hex>` fallback index. That index is read-modify-write: two Jobs
  that attach to the same digest at the same time can lose an entry. The
  next run finds the SBOM missing and attaches it again, so the loss heals.

The check of a generated document (untrusted sidecar output):

- at most the size cap, valid UTF-8, exactly one JSON object, no trailing
  data;
- CycloneDX: `bomFormat` is `CycloneDX` and `specVersion` is `1.<n>`;
- SPDX: `spdxVersion` is `SPDX-2.<n>` and `SPDXID` is `SPDXRef-DOCUMENT`.

The content is not cross-checked against the image. A compromised
generator can write a false SBOM (T38).

### Upstream SBOMs

Under `PreferUpstream` an upstream referrer counts as the child's SBOM when:

- its manifest is an image manifest whose `subject` is the child digest,
- its `artifactType` (or, without one, its config media type) is the media
  type of the configured format, and it has exactly one layer of that type,
- it carries no `dev.tagwarden.*` annotation,
- the layer passes the same document check as a generated SBOM, and the
  referrer fits the referrer budget (`maxArtifactSize`), and
- the referrer copy succeeds.

Otherwise the child gets a generated SBOM. buildkit attestation manifests
in the index and cosign `.sbom` tags are copied as today but do not count:
their binding to a platform is publisher-controlled and they are in-toto
statements or untyped tags. Recognising buildkit SPDX attestations is a
possible later improvement.

### Multi-arch indexes

- Every image child gets its own SBOM, whatever the node architectures of
  the cluster. Attestation manifests are skipped by the gate's content rule.
  A nested index fails generation (`SBOMFailed`), as it fails the gate.
- Admission policies and most tools resolve the reference a pod names,
  which for a multi-arch tag is the index digest. So each child SBOM is
  also attached to the index, as a second small manifest that shares the
  layer blob, with `dev.tagwarden.sbom.platform` set. A single-platform
  image gets one referrer.
- The whole index is published or not. With `required: true` one failed
  child keeps the tag from moving.

### Size limits

- A generated SBOM above 64 MiB is a failure (`TooLarge`). That cap bounds
  the sync container's memory and the `scan` volume. The spike measures
  real sizes; the cap is a constant, not an API field.
- `maxArtifactSize` applies: generated SBOMs share the referrer budget of
  their artifact with the copied referrers. Over the budget is `TooLarge`.
- The generator writes into `scan`; the work layout is bounded by
  `generator.storage` like the gate's `scanner.storage`.

### Signing (step 8)

Optional `signing.keySecretRef` names a Secret in the operator namespace
with a private key. The sync container, not the sidecar, signs: the
generator never sees the key.

- The Job wraps each SBOM in an in-toto statement (predicate type
  `https://cyclonedx.org/bom` or `https://spdx.dev/Document`, subject the
  child digest), signs it as a DSSE envelope and pushes it in the format
  that cosign `verify-attestation --key`, Kyverno and policy-controller
  accept (spike).
- No new dependency: ECDSA P-256 and DSSE are standard library code. The
  cosign encrypted key format needs scrypt and secretbox from
  `golang.org/x/crypto`; the spike checks whether it is already in the
  module graph, otherwise the Secret holds an unencrypted PKCS#8 key and
  the encryption at rest is the Secret store's.
- The key is mounted only in the sync container, never logged, never in
  status, Events, errors or the termination message (tests).
- Under `required: true` a signing failure is an SBOM failure.
- KMS and OpenBao transit are later work, shared with the re-sign feature
  of phase 3.

### Result, status, Events, metrics, audit

Report (termination message): Jobs with an SBOM policy write version 2
with new optional fields; Jobs without it keep writing exactly what they
write today. `syncspec.ParseReport` validates the new fields (T12):

- counts `sbomGenerated`, `sbomUpstream`, `sbomFailed`;
- `sbomFailures`: up to 10 entries `{tag, digest, reason, published}`,
  reasons `GenerationFailed`, `TooLarge`, `AttachFailed`, `SigningFailed`,
  `Missing`; cut to fit, before synced tags are cut;
- `javaScanned` as in the gate.

Exit codes: a tag not published because of `required: true` is a failed
tag, exit 1, so the Job retries. A sidecar that never answers is the same.

Mirror status (image mirrors of an SBOM target only):

- Condition `SBOM`: True with reason `Attached` when every selected tag on
  the target has an SBOM. False with `NotConfigured`, `GenerationFailed`,
  `AttachFailed` or `Missing`, and a message that lists tags, cut at 1024
  bytes. Absent otherwise.
- `Synced` goes False when a tag was not published (`required: true`), as
  for any failed tag. `Ready` stays True.

Events on the mirror: `SBOMFailed` (Warning, once per tag and digest, says
whether the tag was published). Target: `SBOMReady` changes. Generated
mirrors relay to pods: `MirrorRefused` with reason `SBOMMissing` when a tag
was not published.

Metrics:

- `tagwarden_sbom_not_configured{target}` gauge, see above.
- `tagwarden_sbom_failures_total{target,reason,published}` counter, from
  reports.

Audit line, per tag:

```json
{"sbom":{"mode":"Generate","format":"CycloneDX","required":true,
 "platforms":[{"platform":"linux/amd64","digest":"sha256:...","source":"generated","referrer":"sha256:...","size":123456,"javaScanned":false}]}}
```

### Re-scan and the gate

- With the gate on, the scan comes first. A tag blocked by the gate gets no
  SBOM and no referrers, as today.
- Re-scan Jobs do not generate SBOMs.
- Generated SBOMs pass the gate's referrer allowlist: both media types are
  JSON SBOM types.

## Threat model changes

- T1: an SBOM says what is in an image, not that it is safe. Signed SBOMs
  (step 8) let consumers require that Tagwarden mirrored an image, which
  catches images pushed around the mirror.
- T11: SBOM Jobs add the `sbom` native sidecar with the pinned generator
  image, no Secret, no token, `NO_PROXY=*`, the layout read-only; covered by
  `securityDrift` like `scanner`.
- T34: the sidecar protocol gets a second request kind with the same
  checks; the SBOM output cap is 64 MiB.
- New T38, false or missing SBOM: a compromised generator can describe an
  image falsely; the SBOM is never used for a security decision inside
  Tagwarden, the generator image is pinned by digest and mirrored, and
  consumers who need provenance verify the platform signature. Upstream
  referrers that claim `dev.tagwarden.*` annotations are not copied, so an
  upstream publisher cannot pass its SBOM off as generated. Accepted: under
  `PreferUpstream` the SBOM is the publisher's word. Accepted: two targets
  on one registry and project with different policies let tags in through
  the weaker one (reported as `WeakerTargetOnRegistry`).
- New T39 (step 8), signing key theft: key only in a Secret in the operator
  namespace, mounted only in the sync container of SBOM Jobs, never in the
  sidecar, never in status, Events, logs, errors or the report (tests).
  Accepted: a sync container holds the key while it runs, so a compromised
  sync image can sign anything; the same image already holds push rights.

## Decisions to confirm

1. **Enum spelling.** The issue proposes `cyclonedx | spdx-json`. This
   design uses `CycloneDX | SPDX` (Kubernetes API conventions, like the
   other enums of the target). SPDX is always JSON here, since text and
   tag-value SBOMs fail the gate's JSON content rule.
2. **Index-level copies.** Each child SBOM is also attached to the index so
   that policies that resolve the index find it. Costs one small manifest
   per child; the blob is shared.
3. **Scope.** All `Image` mirrors of the target, user-defined and generated.
   The vulnerability gate is limited to generated mirrors; SBOMs are not,
   because the issue asks for every mirrored image.
4. **No retraction.** `required: true` stops new tags. Tags already
   published without an SBOM get one attached on the next run, or are
   reported `SBOMMissing`; they are never untagged.

## Implementation plan

Each step is a PR with tests first.

0. **Spike.** Trivy SBOM from an OCI layout with no network and no DB;
   Java DB need; time, memory and SBOM size for the gate spike images;
   referrers API and tag fallback on the registries listed above; which
   signed attestation format cosign, Kyverno and policy-controller verify
   with a key; whether `golang.org/x/crypto` is in the module graph.
   Results in `docs/design/spikes.md`.
1. **SBOM package** (`internal/sbom`). Formats and media types, document
   check with a size cap (fuzz test), referrer manifest and image for
   push, upstream referrer rules, generated-referrer detection, reserved
   annotation check. Table tests, no I/O.
2. **API.** `spec.sbom` with CEL, target condition `SBOMReady`
   (`NotConfigured`, `WeakerTargetOnRegistry`), the gauge, chart flags.
   Envtest.
3. **Sync integration.** Sidecar request kind, generation per child,
   referrer push (with and without the referrers API, in-process
   registries), present-tag backfill, upstream selection, reserved
   annotation skip, report fields, audit, exit codes. Fake sidecar with
   canned, late, garbage and huge output.
4. **Rendering.** `sbom` sidecar for SBOM Jobs, shared `scanner` sidecar for
   gated Jobs, `securityDrift`, `NotConfigured` handling. Golden test:
   Jobs of targets without an SBOM policy render byte for byte as before.
5. **Status, Events, metrics, pod relay.** Envtest.
6. **e2e on kind.** `Generate` attaches a CycloneDX referrer per platform
   of a multi-arch image; `required: true` with a failing generator
   publishes nothing and reports why; an `ArtifactMirror` cannot weaken the
   target policy.
7. **Docs.** Platform guide, install and NetworkPolicy notes, threat model
   rows, consumer-side check with `oras discover` and `trivy sbom`.
8. **Signing.** Key from a Secret, signed attestation, consumer examples
   for Kyverno and policy-controller.

Later: KMS and OpenBao transit keys; a judged-style status list to skip
referrer lookups; buildkit SBOM attestations under `PreferUpstream`.
