# Audit of user-visible messages

Status: analysis only. No code was changed.

Scope: `main` at `1974244`. PR #87 (`maxListedTags`) and PR #95 (prune)
are in. Line numbers below are on that commit.

Where users see messages:

- `ArtifactMirror`, `ClusterMirrorTarget` and `VulnerabilityException`
  conditions. ArgoCD shows them as `<reason>: <message>` (docs/argocd.md),
  so the final strings below are written in that form.
- Kubernetes Events on the same objects and, for auto-mirror, on Pods.
- Sync Job errors. They travel in the termination message
  (`internal/synccmd`) and end up in `summary()` in
  `internal/controller/status.go:303`.
- Manager flag errors and logs in `cmd/main.go`.

## 1. Summary

Reviewed: 253 `fmt.Errorf` / `errors.New` sites outside tests, 90
`fmt.Sprintf` sites in `internal/controller`, 44 Event call sites.

The Go conventions hold up: no error string ends in punctuation, the only
two upper-case starts are `HTTPS_PROXY` and `CA`, and every wrap but one
deliberate case (`vuln/parse.go:112`) uses `%w`. No message leaks a
credential: `dockerAuth` never quotes the file, cloud auth errors carry the
HTTP status and OAuth codes only, proxy URLs are redacted, and
go-containerregistry redacts query values in the URLs it puts in errors.

The goal of this audit: a user who reads one condition or one Event knows
what failed, on which object, why, and what to do next. A longer message
is fine when it says more. The problems:

1. Length caps cut the useful part. A per-tag error stops at 300 bytes, at
   200 when the report shrinks, and at 256 in the condition. The cause
   and the next step sit at the end of a message, so the cut removes them
   first.
2. The sync summary in `status.go` always prints its counters, even when
   nothing was attempted, says "1 errors", ignores blocked tags and
   truncated error lists, and names only the first failed tag. Every sync
   failure goes through it.
3. Limits hit inside the sync Job do not follow the pattern of
   `limits.go`. They do not name the field, and the value is raw bytes or
   missing.
4. Package prefixes (`sync:`, `tags:`, `spec:`) leak into status, collide
   with field names (`tags:` the package vs `spec.tags` the field) and
   appear mid-string ("1.27: sync: target tag ...").
5. Deterministic failures (listing limit, artifact too large) exit 1, so
   the Job retries them twice and the reason is `SyncFailed`, not
   `ConfigRejected`.
6. Two paths put internal addresses into tenant-visible text: the Job's
   source address check and the scanner probe, which auto-mirror relays to
   Pod Events.
7. Messages that tell a tenant to wait on the platform team rarely say
   why (`ClusterMirrorTarget X is not Ready`), and tenants may not be able
   to read the cluster-scoped object.

Findings listed in section 4, by primary category:

| Category | Count |
|----------|-------|
| Length caps | 1 |
| Grammar and wording | 8 |
| Go conventions | 1 |
| Missing information or next step | 10 |
| Consistency (wording, reasons) | 6 |
| Composition (after wrapping and summary) | 5 |
| Safety | 2 |
| **Listed** | **33** |
| Minor, not listed | 21 |

The minor items are terse sentinel texts that only appear for a forged or
corrupt report (`syncspec/spec.go:634-804`, shown as `Crashed`), spec
validation texts that only appear on controller and Job version skew, CLI
texts of the sync subcommand that only an operator sees, length limits
that do not echo the actual length, and the `internal/sbom` package (30
sites), which nothing imports yet.

## 2. Length budget

Each cap and the hard limit behind it:

| Where | Today | Hard limit | Proposed |
|-------|-------|------------|----------|
| Per-tag error in the Job (`sync.maxMessage`, `sync.go:54`) | 300 | none | 1024 |
| Errors kept when the report must shrink (`synccmd.keptErrors` / `keptErrorLen`, `synccmd.go:576-577`) | 3 x 200 | 4096 for the whole report (kubelet termination message) | 2 x 1024 |
| Quoted error in the condition (`controller.maxErrorLen`, `status.go:43`) | 256 | 32768 (condition message) | 1024 |
| Scanner probe message (`controller.maxMessage`, `scanner.go:52`) | 256 | 32768 | 1024 |
| Event note | uncapped | 1024 (`events.k8s.io/v1` note) | keep each Event text under 1024 |

`encode` already keeps the first errors before the synced tags when the
report does not fit, and sets `ErrorsTruncated` when it cuts. Two errors
of 1 KiB leave about 2 KiB for the rest of the report. The summary quotes
only the first error, so the second one is a spare.

Cut at a clause boundary when a cut is still needed: keep the head (what
and why) and the last clause (what to do), drop the middle (wrapped
transport detail), mark the gap with `...`.

## 3. Proposed conventions

1. **Say what, where, why and what to do, in that order.** Name the
   object, the tag or repository, the actual value, the allowed value and
   the field to change. Length is not a reason to drop any of them.

2. **No package prefixes in errors that can reach status.** Name the step
   instead. A package name means nothing to a user, and `tags:` reads like
   the field.
   - Before: `1.27: sync: target tag points to a different digest than upstream`
   - After: `1.27: upstream tag moved ...`

3. **Limits use one pattern: what, actual value, field path, owner.**
   This is what `limits.go` already does. The sync Job does not know the
   target name, so it says "of the ClusterMirrorTarget"; the mirror's
   `spec.targetRef` makes that unambiguous.
   - Before: `artifact too large: 5368709120 > 2147483648`
   - After: `artifact docker.io/library/nginx:1.27 is 5Gi, above the limit spec.limits.maxArtifactSize 2Gi of the ClusterMirrorTarget; ask the platform team to raise the limit, or exclude this tag with tags.exclude`

4. **Field paths are the API's dotted paths.** `tags.include[0]`,
   `spec.limits.maxListedTags`, `policy.onTagMutation`. Never Go names
   (`MaxTags`) or `field: ` prefixes.
   - Before: `tags: include[0]: error parsing regexp: ...`
   - After: `tags.include[0]: error parsing regexp: ...`

5. **Counts agree with their noun. On failure, drop zero counters and
   name the failed tags.** The success summary keeps its counters (ArgoCD
   shows it as the healthy message).
   - Before: `copied 0, skipped 0, mutated 0, failed 0; 1 errors, first: ...`
   - After: `1 error: ...`
   - Before: `copied 2, skipped 0, mutated 0, failed 3; 3 errors, first: ...`
   - After: `copied 2, failed 3; 3 tags failed (1.27, 1.28, 1.29), first error: ...`

6. **One fact per clause, clauses joined with `; `, no `;` inside a list.**
   - Before: `40 prerelease skipped; set allowPrerelease; copied 0, ...`
   - After: `40 prereleases skipped (set tags.allowPrerelease: true to keep them)`

7. **End with the next step when the reader can take one.** Name the
   field to change, or say who acts (`ask the platform team`), as
   `AutoMirrorDisabled` already does.
   - Before: `ClusterMirrorTarget shared is not Ready`
   - After: `ClusterMirrorTarget shared is not Ready (SecretNotFound: the credentials Secret of the target does not exist); no image is mirrored until it is fixed; ask the platform team`

8. **Explain a reason code in words when the message quotes one.**
   `DeadlineExceeded`, `BackoffLimitExceeded` and the target's Ready reason
   are codes. Follow each with what it means here.

9. **The message does not repeat the reason, and one situation has one
   reason.** A relay that wraps a condition under another reason prefixes
   the inner reason only when it differs.
   - Before: Event reason `SyncFailed`, message `SyncFailed: copied 0, ...`
   - After: Event reason `SyncFailed`, message `1 error: ...; see ArtifactMirror team-a/nginx`

10. **Sizes and durations are human-readable.** Sizes as
    `resource.Quantity` strings, durations without zero units, whole days
    as days.
    - Before: `below minSyncInterval 1h0m0s`
    - After: `below minSyncInterval 1h`

11. **Lists are comma-separated, never Go `%v`.**
    - Before: `tags [1.27 1.28]`
    - After: `tags 1.27, 1.28`

12. **Tenant-visible text never carries addresses the cluster resolved,
    denied CIDRs or in-pod paths.** Say what was refused and who can fix
    it. Put the detail in the Job's JSON stdout or the controller log,
    where the platform team looks.
    - Before: `source: registry.example.com resolves to 10.96.0.10 in denied CIDR 10.96.0.0/12`
    - After: `source registry registry.example.com resolves to an address inside the cluster network, which sync Jobs may not reach; ask the platform team to check the registry DNS name or the denied CIDRs`

Constraint for every sync engine change: `synccmd.audit` splits each entry
of `res.Errors` on the first `": "` to attach it to the audit line of that
tag (`internal/synccmd/synccmd.go:494`). Per-tag errors must keep the
`<tag>: <message>` shape.

## 4. Findings

Most user-impacting first within each area.

### Length caps

| ID | file:line | Problem | Proposed change |
|----|-----------|---------|-----------------|
| B1 | `internal/sync/sync.go:54`, `internal/synccmd/synccmd.go:576-577`, `internal/controller/status.go:43`, `internal/controller/scanner.go:52` | Four caps between 200 and 300 bytes. The proposed messages put the next step last, and the cap cuts it first. | Raise per section 2. Cut at a clause boundary and keep the last clause. Test that every "after" string in section 5 reaches the condition whole. |

### Sync engine (`internal/sync`, `internal/synccmd`, `internal/tags`)

| ID | file:line | Problem | Proposed message |
|----|-----------|---------|------------------|
| S1 | `internal/sync/sync.go:308` | Listing limit: `source has more than %d tags, the limit (maxListedTags of the ClusterMirrorTarget)`. "the limit" dangles, there is no field path and no repository. The count is a lower bound because listing stops, so the real number cannot be shown. | `listing tags of <source repo> stopped after %d tags: the repository has more than spec.limits.maxListedTags (%d) of the ClusterMirrorTarget allows; list the wanted versions in tags.tags, which skips listing, or ask the platform team to raise maxListedTags` |
| S2 | `internal/sync/sync.go:300` | Page cap: no repository, no hint. | `listing tags of <source repo> stopped after %d pages: the registry keeps returning more pages; list the wanted versions in tags.tags, which skips listing` |
| S3 | `internal/sync/sync.go:51`, `:174`, `:359` | `ErrTagMutated` carries `sync:` and lands mid-string after the tag. No hint about the policy or what to do. | `upstream tag moved: target has %s, upstream now has %s; the target tag was kept because policy.onTagMutation of the ClusterMirrorTarget is Fail; check the upstream release, then ask the platform team to re-tag or set onTagMutation` (full digests: they let the user compare with the upstream registry) |
| S4 | `internal/sync/sync.go:449`, `:468` | Raw byte counts with `>`, no field, no artifact. | `artifact <repo>:<tag> is %s, above the limit spec.limits.maxArtifactSize %s of the ClusterMirrorTarget; exclude the tag with tags.exclude or ask the platform team to raise the limit` and `referrers (signatures, SBOMs, attestations) of <repo>:<tag> total %s, above spec.limits.maxArtifactSize %s ...` (sizes via `resource.NewQuantity(n, resource.BinarySI)`) |
| S5 | `internal/sync/sync.go:432` | `platform linux/arm64 not in source`: no field, no list of what the source has. | `requiredPlatforms lists linux/arm64, but the source image has only linux/amd64, linux/s390x; remove it from requiredPlatforms or pick a tag built for it` |
| S6 | `internal/sync/sync.go:295`, `:304`, `:320`, `:329`, `:364`, `:390` | ggcr errors pass through as is. A 401 or 403 gives no hint, and a registry error with detail prints a Go map (`; [map[Action:pull ...]]`, from `transport.Diagnostic.String`). | Keep the wrap and add a hint on `transport.Error` status 401/403: `...: 401 Unauthorized: the source registry refused the credentials; check sourceCredentials of the ClusterMirrorTarget` (target side: `the target credentials Secret`). Replace the map with `code: message` pairs. |
| S7 | `internal/synccmd/synccmd.go:246`, `:447` | A missing or unreadable credentials file shows the in-pod path (`open /var/run/...: no such file or directory`) and not which Secret or field to check. | `target credentials: the Secret named in the ClusterMirrorTarget is not mounted or not readable in the sync Job; ask the platform team to check that it exists and has the expected key` (log the path on stdout) |
| S8 | `internal/sync/sync.go:51`, `:198`, `:222`, `:231`, `:295`, `:300`, `:304`, `:308`, `internal/sync/gate.go:100`, `internal/tags/select.go:104`, `internal/syncspec/spec.go:328-356` | Package prefixes are inconsistent: 8 of 31 sites in `sync.go` use `sync:`, `tags` uses `tags:` (the field name too), `syncspec` uses `spec:` and `report:`, `synccmd` and `vuln` use none. | Drop `sync:` and `tags:` from errors that reach status (convention 2). `spec:` can stay: it only appears for version skew and says which document is bad. |
| S9 | `internal/sync/sync.go:300-308`, `:449`, `:468` with `internal/synccmd/synccmd.go:136-139` and `internal/synccmd/gate.go:115` | Deterministic failures exit 1 (`ExitSyncFailed`). `notRetryable` maps only scan-blocked runs to exit 3, so the pod failure policy does not stop a listing or size limit, the Job runs two more times, and the reason is `SyncFailed`. A listing over the limit lists up to 10,000 tags three times. | Not a wording change. Exit 3 for the listing limit and the size limit, reason `ConfigRejected`. A refused mutation stays exit 1: `notRetryable` excludes `ErrTagMutated` on purpose, and changing that needs its own decision. |

### Controller conditions (`internal/controller`)

| ID | file:line | Problem | Proposed message |
|----|-----------|---------|------------------|
| C1 | `internal/controller/status.go:316` | "1 errors". Appears on every failed sync with one error. | `1 error: <e>`; from two up `%d tags failed (<tags>), first error: <e>`, with the tags taken from the `<tag>: ` prefix of each kept error and `and %d more` past ten |
| C2 | `internal/controller/status.go:304-307` | Four counters even when nothing was attempted (listing failed, setup failed). They push the useful text back. PR #95 added `pruned %d`. | When `Selection == nil` and all counters are zero, print only the errors. On failure print non-zero counters only, `pruned` included. Keep all counters on success. |
| C3 | `internal/controller/status.go:304` | Gated runs: blocked tags are not counted. A run where the gate blocked every tag reads `copied 0, skipped 0, mutated 0, failed 0`. `Report.Blocked` exists. | Add `blocked %d by the vulnerability gate` when non-zero |
| C4 | `internal/controller/status.go:311-316` | The error count is `len(r.Errors)` after the Job cut the list to fit 4096 bytes. `ErrorsTruncated` is never read, so 40 failed tags can show as `3 errors`. | Count from `r.Failed`, and add `(error list truncated; the sync Job log has all of them)` when `ErrorsTruncated` is set |
| C5 | `internal/controller/status.go:188`, `:201` | `Job X exited with code unknown: no sync container result: DeadlineExceeded`. "exited with code unknown" is wrong when the container never ended, and the Job reason is not explained. | `Job X ended without a sync result (DeadlineExceeded: the Job ran longer than its 1h deadline; a large first sync can need more, ask the platform team)`; for `BackoffLimitExceeded`: `(BackoffLimitExceeded: the sync pod failed 3 times; kubectl logs job/X shows why)` |
| C6 | `internal/controller/status.go:333` | The selection note puts `; set allowPrerelease` inside a comma list and then appends the counters with another `;`. Plurals are wrong (`40 prerelease skipped`). | `no tags selected from 120 listed: 80 removed by tags.include/tags.exclude, 40 prereleases skipped (set tags.allowPrerelease: true to keep them)` and no counters (C2) |
| C7 | `internal/controller/artifactmirror_controller.go:224` | `ClusterMirrorTarget X is not Ready` without the cause. Tenants often cannot read the cluster-scoped object. | `ClusterMirrorTarget %s is not Ready (%s: <what the reason means>); no image is mirrored until it is fixed; ask the platform team`. Map each target Ready reason to a fixed sentence. The target message can quote Secret names from the operator namespace, so do not copy it. |
| C8 | `internal/controller/gate.go:77`, `internal/controller/artifactmirror_controller.go:250` | A gate without a usable scanner under `onScanError: Block` says "not configured" twice, because `problem` starts with it, and does not say who acts. | `vulnerability gate of ClusterMirrorTarget %s has no usable scanner (%s); onScanError is Block, so nothing is copied until the platform team configures one`, with `problem` minus its `not configured: ` prefix. Reason: see the note below the table. |
| C9 | `internal/controller/gate.go:189` | Report mode: `gate enabled but scanner not configured; images are copied unscanned` names neither the target nor who acts. | `vulnerability gate of ClusterMirrorTarget %s has no usable scanner; onScanError is Report, so images are copied without a scan; ask the platform team` |
| C10 | `internal/controller/artifactmirror_controller.go:408`, `internal/syncspec/spec.go:356` | `tags: include[0]: ...` while `limits.go` writes `tags.keepLatest`. | `tags.include[0]: ...` (pass the full path into `compilePatterns`, or prefix with `tags.` without the colon) |
| C11 | `internal/controller/artifactmirror_controller.go:207` | Sync-now refusal says `ArtifactMirror is not Ready: TargetConflict` and drops the message that explains it. | `sync now refused: ArtifactMirror is not Ready (%s): %s` with the Ready message |
| C12 | `internal/controller/artifactmirror_controller.go:302` | `apierrors.IsInvalid` passes the raw API error (`CronJob.batch "..." is invalid: spec...`). It names an object in the operator namespace. | `the API server rejected the sync CronJob rendered from this mirror: %s` with the field causes from `StatusDetails.Causes` only |
| C13 | `internal/controller/automirror.go:332` | `... autoMirror.maxMirrorsPerNamespace %d of %s`: the kind is missing. | `... of ClusterMirrorTarget %s; delete unused generated mirrors or ask the platform team to raise the limit` |
| C14 | `internal/controller/clustermirrortarget_controller.go:186`, `:363`, `internal/controller/scanner.go:237`, `internal/registry/transport.go:79` | Three phrasings for one problem: `holds no PEM certificate`, `CA bundle holds no PEM certificate`, `registry: CA bundle contains no PEM certificate`. | `Secret %s key %s has no PEM certificate` everywhere a Secret is known; `CA bundle has no PEM certificate` otherwise |
| C15 | `internal/controller/limits.go:152`, `internal/controller/syncnow.go:142`, `internal/controller/vulnerabilityexception_controller.go:95` | Go duration format: `runs 30m0s apart`, `minSyncInterval 1h0m0s`, `expires 2160h0m0s after creation`. | `30m`, `1h`, `90d`: a formatter that drops zero units and prints whole days as days, since the API documents 90 days |
| C16 | `internal/controller/status.go:253` | A failed re-scan appends `rescan failed: copied 0, skipped 0, mutated 0, failed 1`. Copied and skipped mean nothing for a re-scan. | `rescan failed for 1 of 12 tags (1.27): <e>; the tags keep their last verdict` |

C8 reason: convention 9 suggests `NotConfigured`, the reason `VulnerabilityGate` uses for the same cause under `Report`. The design (`docs/design/vulnerability-gate.md:893`, `:1416`) chose `ScannerUnavailable` on `Ready` on purpose, and `gate_status_test.go:559`, `:562` assert it. The message fix does not need the rename. Rename only together with those two design lines and the tests, and note it in the changelog: alerts may match on the reason.

### Events

| ID | file:line | Problem | Proposed message |
|----|-----------|---------|------------------|
| E1 | `internal/controller/automirror.go:432`, `:437`, `:442` | Pod relay copies the condition as `<reason>: <message>`. With reason `SyncFailed` the Event reads `SyncFailed` / `SyncFailed: copied 0, skipped 0, ...`, and it does not say which mirror to look at, unlike `relayGate` (`:461`). | Prefix only when the condition reason differs from the Event reason; append `; see ArtifactMirror %s/%s` |
| E2 | `internal/controller/automirror.go:353`, `:446` | Two phrasings for the same Event (`Requested mirror of %s tags %v as ...` and `Mirror of %s tags %v requested as ...`), and `%v` prints `[1.27 1.28]`. | One text: `requested mirror of %s tags %s as ArtifactMirror %s/%s` with `strings.Join(tags, ", ")` |
| E3 | `internal/controller/automirror.go:339`, `:383` | `TooManyTags`: the first form does not name the limit owner or the dropped tags, the second prints them with `%v`. | `%s: %d tags requested, above autoMirror.maxExplicitTags %d of ClusterMirrorTarget %s; not mirrored: %s; pin fewer tags in this namespace or ask the platform team to raise the limit` for both |
| E4 | `internal/controller/gate.go:472` | `ScanFailed: tag 1.27 (sha256:...) could not be scanned, copied`. "copied" is ambiguous for a fail-open security event. | `tag 1.27 (sha256:...) could not be scanned (ScanFailed: <what it means>); copied without a vulnerability verdict because onScanError is Report` and `...; not copied because onScanError is Block` |
| E5 | `internal/controller/automirror.go:202` | `TargetNotReady: ClusterMirrorTarget X is not Ready` on a Pod: same gap as C7. | Same text as C7 |
| E6 | `internal/controller/automirror.go:347`, `:397` | `%s cannot be mirrored: %v` and `%s cannot be updated: %v` quote the raw API error on a tenant Pod. | Same treatment as C12 |

### Safety

| ID | file:line | Problem | Proposed message |
|----|-----------|---------|------------------|
| X1 | `internal/syncspec/spec.go:481`, `:485`, called from `internal/synccmd/synccmd.go:376-394` | The Job writes the address the cluster DNS returned and the denied CIDR into the report, so the tenant's `Synced` condition shows, for example, the service CIDR. Low impact (the host must be in `allowedSources`), but convention 12 rules it out. | `source registry %s resolves to an address inside the cluster network, which sync Jobs may not reach; ask the platform team to check the registry DNS name or the denied CIDRs`. Write the address and CIDR on the Job's JSON stdout. The controller check sees only literal addresses typed by the tenant; there `source 127.0.0.1 is an internal address; use the registry host name` is enough. |
| X2 | `internal/controller/scanner.go:86` with `internal/controller/automirror.go:469` | `address refused: resolves to 10.0.0.5 in denied CIDR ...` on `ScannerReady`. That is the platform team's object, but `relayGate` copies the message into Warning Events on tenant Pods. The text also has no subject. | On the target: `scanner address %s resolves to %s in denied CIDR %s; the controller refuses it` (platform team only). In the Pod relay, pass the reason only: `scanner of ClusterMirrorTarget %s is unavailable (%s); images are not mirrored; ask the platform team` |

### CLI (`cmd/main.go`)

| ID | file:line | Problem | Proposed message |
|----|-----------|---------|------------------|
| L1 | `cmd/main.go:83-99` | The gate flags must be set together, but setting only `--trivy-url` fails with `--trivy-image must be pinned by digest`, which suggests a wrong value, not a missing one. | When some but not all are empty: `--trivy-image, --trivy-version and --trivy-url must be set together; missing: --trivy-image`. Then the format checks as today, with the value as a log key (as `--argocd-tracking` does). |

## 5. Full strings for the key paths

Each "before" follows the code: the error text in the Job, `synccmd.run`
(which adds the run-level error only when no per-tag error exists),
`summary()` and `applyResult()`, and ArgoCD's `<reason>: <message>`.
`<job>` stands for a Job name. The "after" assumes the conventions above
and the PRs in section 6; it is a target, not tested output. B1 must land
first: most "after" strings are longer than today's caps.

**K1. Source with more than 10,000 tags (the triggering case)**

Before:

    SyncFailed: copied 0, skipped 0, mutated 0, failed 0; 1 errors, first: sync: source has more than 10000 tags, the limit (maxListedTags of the ClusterMirrorTarget)

After (S1, S9, C1, C2):

    ConfigRejected: listing tags of docker.io/renovate/renovate stopped after 10000 tags: the repository has more than spec.limits.maxListedTags (10000) of the ClusterMirrorTarget allows; list the wanted versions in tags.tags, which skips listing, or ask the platform team to raise maxListedTags

**K2. Upstream tag moved, policy Fail**

Before:

    SyncFailed: copied 0, skipped 11, mutated 1, failed 0; 1 errors, first: 1.27.3: sync: target tag points to a different digest than upstream: target sha256:<64 hex>, upstream sha256:<64 hex>

After (S3, S8, C1, C2; the reason stays `SyncFailed`, see S9):

    SyncFailed: skipped 11, mutated 1; 1 error: 1.27.3: upstream tag moved: target has sha256:<64 hex>, upstream now has sha256:<64 hex>; the target tag was kept because policy.onTagMutation of the ClusterMirrorTarget is Fail; check the upstream release, then ask the platform team to re-tag or set onTagMutation

**K3. Private source without valid credentials**

Before:

    SyncFailed: copied 0, skipped 0, mutated 0, failed 3; 3 errors, first: 1.27: resolve source tag: HEAD https://registry.example.com/v2/team/app/manifests/1.27: unexpected status code 401 Unauthorized (HEAD responses have no body, use GET for details)

After (S6, C1, C2):

    SyncFailed: failed 3; 3 tags failed (1.27, 1.28, 1.29), first error: 1.27: resolve source tag: HEAD https://registry.example.com/v2/team/app/manifests/1.27: 401 Unauthorized: the source registry refused the credentials; check sourceCredentials of the ClusterMirrorTarget

**K4. Artifact over the size limit**

Before:

    SyncFailed: copied 0, skipped 4, mutated 0, failed 1; 1 errors, first: 2.0.0: artifact too large: 5368709120 > 2147483648

After (S4, S9, C1, C2):

    ConfigRejected: skipped 4, failed 1; 1 error: 2.0.0: artifact registry.example.com/team/app:2.0.0 is 5Gi, above the limit spec.limits.maxArtifactSize 2Gi of the ClusterMirrorTarget; exclude the tag with tags.exclude or ask the platform team to raise the limit

**K5. No tag matches the policy**

Before:

    NoTagsSelected: no tags selected from 120 listed, 80 removed by include/exclude, 40 prerelease skipped; set allowPrerelease; copied 0, skipped 0, mutated 0, failed 0

After (C2, C6):

    NoTagsSelected: no tags selected from 120 listed: 80 removed by tags.include/tags.exclude, 40 prereleases skipped (set tags.allowPrerelease: true to keep them)

**K6. Job killed by the deadline**

Before:

    Crashed: Job <job> exited with code unknown: no sync container result: DeadlineExceeded

After (C5):

    Crashed: Job <job> ended without a sync result (DeadlineExceeded: the Job ran longer than its 1h deadline; a large first sync can need more, ask the platform team)

**K7. Gate with `onScanError: Block` and no scanner (`Ready`)**

Before:

    ScannerUnavailable: gate enabled but scanner not configured on ClusterMirrorTarget shared (not configured: set scanner.url or enable the chart's Trivy server); onScanError is Block, images are not copied

After (C8, reason unchanged):

    ScannerUnavailable: vulnerability gate of ClusterMirrorTarget shared has no usable scanner (set scanner.url or enable the chart's Trivy server); onScanError is Block, so nothing is copied until the platform team configures one

**K8. Source host that resolves to an internal address**

Before:

    ConfigRejected: copied 0, skipped 0, mutated 0, failed 0; 1 errors, first: source: registry.example.com resolves to 10.96.0.10 in denied CIDR 10.96.0.0/12

After (X1, C2):

    ConfigRejected: source registry registry.example.com resolves to an address inside the cluster network, which sync Jobs may not reach; ask the platform team to check the registry DNS name or the denied CIDRs

**K9. K1 as a Warning Event on an auto-mirrored Pod**

Before (Event reason `SyncFailed`):

    SyncFailed: copied 0, skipped 0, mutated 0, failed 0; 1 errors, first: sync: source has more than 10000 tags, the limit (maxListedTags of the ClusterMirrorTarget)

After (E1 on top of K1; reason `SyncFailed`, the inner reason differs so it stays):

    ConfigRejected: listing tags of docker.io/renovate/renovate stopped after 10000 tags: the repository has more than spec.limits.maxListedTags (10000) of the ClusterMirrorTarget allows; list the wanted versions in tags.tags, which skips listing, or ask the platform team to raise maxListedTags; see ArtifactMirror team-a/renovate-renovate

All "after" strings fit the proposed 1024-byte caps, the Event note limit
included. K1, K2 and K9 do not fit today's 256-byte condition cap.

## 6. Suggested pull requests

Each one is small and can be reviewed on its own. Order is by impact.

1. **`fix: raise message length caps`** (`sync.go`, `synccmd.go`,
   `status.go`, `scanner.go`). B1. Comes first: every other PR writes
   longer messages. Add a test that fills the report with errors of the
   new size and checks `encode` stays under 4096 bytes.
2. **`fix: clearer sync summary in status`** (`status.go`,
   `status_test.go`). C1, C2, C3, C4, C6, C16. Pure string building,
   table tests only. Every sync failure message changes: say so in the
   changelog, in case someone matches on it.
3. **`fix: keep internal addresses out of tenant messages`** (`synccmd`,
   `syncspec`, `scanner.go`, `automirror.go`). X1, X2, S7. Add the test
   the hard rules ask for: assert the address and CIDR do not appear in
   the report or the Events. Touches T8 and T16 wording in the threat
   model.
4. **`fix(sync): name the limit, the field and the next step in sync
   errors`** (`internal/sync/sync.go`, `internal/tags/select.go`). S1-S6,
   S8. Keep the `<tag>: <message>` shape for the audit line.
5. **`fix(sync): stop retrying limit failures`** (`synccmd`, `sync`). S9.
   Behavior change: exit 3 for the listing limit and the size limit,
   reason `ConfigRejected`. Needs an envtest and a note in the threat
   model (T22 says the error is reported in status). A refused mutation
   keeps exit 1.
6. **`fix(controller): say why and who acts in Ready messages`**
   (`artifactmirror_controller.go`, `gate.go`, `automirror.go`). C7, C8,
   C9, C11, C12, C13, E5, E6. Keep the `ScannerUnavailable` reason unless
   the design doc changes with it (see C8).
7. **`fix(automirror): consistent Pod Events`** (`automirror.go`,
   `gate.go`). E1, E2, E3, E4.
8. **`chore: consistent wording for CA bundles, durations, field paths
   and gate flags`**. C10, C14, C15, L1.

Not proposed: a shared message package or error types per message. The
conventions plus table tests on the final strings cover it.
