# Prune tags that a mirror no longer selects

Phase 4 of threat model T13. `keepLatest` and `semverRange` select what a
run copies, but tags that fall out of the selection stay on the target
forever. A `renovatebot/charts/renovate` mirror with `keepLatest: 5` had 8
tags in Harbor after two days. Prune deletes those tags.

Two PRs, in this order:

1. Issue #71: Harbor tag delete. Harbor refuses
   `DELETE /v2/<repo>/manifests/<tag>` (`UNSUPPORTED`), so Untag fails there
   today and a prune built on the same call would too.
2. Prune itself, on top of PR 1.

## PR 1: Harbor tag delete (#71)

- **`ClusterMirrorTarget.spec.registryFlavor`**, enum `Harbor`, empty means
  generic OCI. Explicit, no probing.
- **Delete path.** With `Harbor` the Job deletes a tag with
  `DELETE /api/v2.0/projects/{project}/repositories/{repo}/artifacts/{digest}/tags/{tag}`,
  `{repo}` URL-encoded twice as Harbor requires. The call is scoped to the
  digest, so it also closes the resolve-then-delete race of T13 on Harbor.
  It uses the target Secret credentials (basic auth) and the same transport
  as pushes (CA, client certificate, proxy). Workload identity auth with
  `Harbor` is refused by CEL: Harbor has no such auth.
- **One function for both callers.** `deleteTag(ctx, tag, digest)` in the
  sync package picks the OCI or the Harbor path. Untag moves onto it.
- **Permissions.** The robot account needs Harbor's "delete tag" permission
  on the project. `docs/install.md` says so next to the Untag notes.
- **Not found.** A 404 means the tag is not on that digest (gone or
  moved). The deleter returns `ErrTagNotFound`; Untag reports it as
  `UntagRefused`, prune drops the tag from `owned`. Other errors keep the
  tag.
- **Tests.** `httptest` server checks method, path, encoding and auth,
  and that errors carry no credentials or server text.

## PR 2: prune

### API

- **`ArtifactMirror.spec.tags.prune: bool`**, default false (opt-in, T13).
- **`ArtifactMirror.status.owned []{tag, digest}`**, max 200,
  `listType=atomic`. The record of tags Tagwarden put on the target for
  this mirror. `status.synced` cannot serve: it is replaced every run.

### Owned record (controller)

- After every sync report, every `synced` entry the Job marked `copied`
  (copied or overwritten in this run) is merged into `owned` by tag; the
  run's digest wins. A skipped tag was on the target already, so the
  mirror cannot show it put the tag there: it never joins `owned` and
  never changes a recorded digest. With `onTagMutation: Ignore` a human
  push is therefore never adopted.
- Entries the report lists as pruned are removed. Entries for tags the run
  saw missing or moved on the target (`dropped`) are removed too, but only
  when tag and digest match the record and the run did not sync the tag.
- Over 200 entries the oldest versions are dropped from the record (not
  from the registry) and the Synced condition says so. They are then never
  pruned: fail safe.
- Tags on the target before the mirror recorded them (before this change,
  or pushed by hand) are never in `owned` and never pruned, also when
  their digest matches the source at the first sync. No backfill.
- `owned` is kept with `prune` off as well, so turning it on later prunes
  what the mirror created meanwhile.

### Candidates (controller)

- `prunable` in the Job spec: `owned` minus tags held by other mirrors of
  the same target repository, through any target on the same registry. A
  mirror with tag patterns holds every tag, so prune does nothing then and
  the Synced message says why.
- These are the hold rules of `untaggable()` in `internal/controller/gate.go`.
  They move to one shared function used by Untag and prune.
- Only set when `prune: true`, the mirror is not suspended or refused, and
  the target allows the path (T17).

### Delete (sync Job)

- After all copies of a run, the Job deletes every `prunable` tag that is
  not in the run's selection.
- A prunable tag that the selection would pick had the source listed it
  (the policy run over the listing plus the prunable tags) is kept and
  reported in errors. A valid but incomplete listing cannot prune the
  newest tags.
- Before each delete it resolves the tag on the target and deletes only if
  it still points at the digest in `owned`. A moved tag is kept and dropped
  from `owned`.
- Never in a re-scan Job.
- Prune is skipped for the whole run when the listing failed, the
  selection is empty, any tag failed, or a mutated tag was refused. A bad
  upstream response must not empty the target.
- Only the tag is deleted, never the digest. Disk space comes back through
  Harbor GC with "Allow garbage collection on untagged artifacts".
- A failed delete keeps the tag, lists `"<tag>: prune failed, kept: ..."`
  in errors (the per-tag format the audit log parser expects) and does not
  change the exit code, as with `UntagFailed`.

### Report, status, Events

- The termination message gets `pruned []{tag, digest}`, validated like
  `synced` (T12): a pruned tag must be in the `prunable` list the
  controller sent, with the same digest, otherwise the report is `Crashed`.
- Accepted: two Jobs that overlap and both prune the same tag. The second
  report is refused as `Crashed` because the first already removed the tag
  from `owned`. Only the status is affected; the next run is clean.
- The Synced message gets a `pruned N` counter.
- Event `TagPruned` per tag, capped like the gate Events.

### Out of scope

- Prune on mirror deletion.
- Deleting artifacts or digests.
- Backfilling `owned` from what is on the target.
- Rate or count caps per run beyond `keepLatest` (max 100).

### Tests

- Table tests: `owned` merge, cap, removal on pruned or missing.
- Table tests: shared hold function (explicit holds, pattern holds,
  deleted mirrors, other targets on the same registry).
- Sync tests on the in-memory ggcr registry: prune of a dropped tag,
  moved tag kept, each skip condition, failed delete kept.
- Report validation: pruned tag outside `prunable` gives `Crashed`.
- Docs: README example, `docs/install.md`, sample, threat model T13 marks
  phase 4 done.
