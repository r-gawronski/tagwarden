# Auto-mirror from pod annotations

Issue #22. A pod annotated with `tagwarden.dev/auto-mirror: <target>` gets
all its images mirrored. Nodes pull through a containerd mirror that
rewrites to the target project, so teams keep upstream image names.

## Decisions

- **Opt-in per target.** `ClusterMirrorTarget.spec.autoMirror` has
  `enabled`, `project`, `schedule` (default `0 */6 * * *`) and
  `maxMirrorsPerNamespace` (default 20, max 200). CEL requires `project` to be
  listed in `projects` and must not set `allowRepositoryOverride`: the node
  rewrite maps a path to one source, and an override project would let a
  tenant bind that path to another. Without `enabled` the pod only gets an
  `AutoMirrorDisabled` Warning Event.
- **Generated mirrors are ordinary `ArtifactMirror` objects.** The
  ArtifactMirror controller authorizes, renders and syncs them like any
  other, so project policy, `allowedSources`, path conflicts and limits
  (including `minSyncInterval` on the schedule) apply unchanged. The auto-mirror
  controller never renders CronJobs.
- **One mirror per namespace and source repository.** Name
  `auto-<16 hex of sha256(registry/repository)>`, labels
  `tagwarden.dev/generated=true` and `tagwarden.dev/auto-target=<target>`.
  The registry is canonical (Docker Hub names fold to `docker.io`, a bare
  repository gets `library/`).
- **Explicit tags only.** The union of tags seen on pods, sorted, at most
  100 and at most the target's `maxExplicitTags`. Tags that do not fit raise a
  `TooManyTags` pod Event. Tags are never removed; pruning belongs to a later
  phase. A user-defined mirror is never modified.
- **User mirrors win.** A non-generated mirror with the same source and
  target path gives `AlreadyMirrored` and no generated mirror. A
  non-generated mirror that squats the generated name gives `MirrorRefused`
  (`NameConflict`).
- **Sync right away through the existing sync-now mechanism.** When a
  generated mirror is created or gains a tag, the controller sets
  `tagwarden.dev/sync-now` to a timestamp. `minSyncInterval` and the one-Job-at-a-time
  rule from the sync-now handling apply, so a burst of pods cannot start a
  burst of Jobs. This also covers the auto-mirror triggers of #26. There is
  no separate `runOnChange` field.
- **Image refs.** `repo:tag` and `repo:tag@digest` (the tag is mirrored).
  A ref that points at the target registry and `autoMirror.project` is mapped
  back to the upstream source through `allowedSources`. Digest-only refs get
  `DigestOnlyNotSupported`. Untagged refs would mean `latest`, a moving tag
  nobody chose, so they get `ImplicitLatestNotSupported`.
- **Namespace check first.** The controller checks the project's
  `namespaceSelector` before creating anything and refuses with
  `MirrorRefused` (`ProjectNotAllowed`), so a namespace that may not use the
  project cannot fill the quota with failing objects.
- **Existing generated mirrors are verified.** A mirror with the generated
  label but another source or target is left alone (`NameConflict`). One
  that only drifted in project, schedule or `target.repository` (the platform
  changed `autoMirror`) is patched back.
- **One bad image does not stop the rest.** Sources are handled
  independently; an object the API rejects gives an `InvalidImage` Event and
  the others proceed.
- **Quota.** The count of generated mirrors per namespace and target is
  read from the API server just before a create, so a stale cache cannot
  overshoot. Over quota gives `MirrorRefused` (`QuotaExceeded`).
- **Feedback.** Pod Events `MirrorRequested`, `MirrorRefused` and `SyncFailed`.
  The controller relays any `Ready=False` or `Synced=False` condition of
  the generated mirror with its reason and message, with no fixed list of
  reasons. It watches generated mirrors, so a change shows up on the pod.
  Events are deduplicated per pod and image: one is recorded only when
  the state changes. The state map is dropped when a pod disappears and
  cleared when it grows past 10000 pods.
- **Memory.** Pods come from a dedicated informer cache with a transform
  that keeps name, namespace, UID, resource version, deletion timestamp and,
  for annotated pods only, the auto-mirror annotation and the name and
  image of each container and init container. The informer still lists and
  watches all pods, so API server and CPU cost grow with the pod count. The main manager cache keeps its
  operator-namespace restriction on pods.
- **RBAC.** Pods get/list/watch cluster-wide, `artifactmirrors`
  create/patch, Events as before. See T28 in the threat model.

## Vulnerability gate (#21)

The gate applies to generated mirrors, because they take the normal sync
path. A gate result such as a `VulnerabilityBlocked` reason on `Ready` or
`Synced` reaches the pod as `MirrorRefused` or `SyncFailed` with that
reason and message, without changes to this controller.

## Not done

- Pruning tags that no pod uses (phase 4).
- Digest-only refs (needs digest mirroring).
- Ephemeral containers; only containers and init containers are read.
