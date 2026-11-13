# Changelog

All notable changes to this project are documented in this file.

Entries come from the Conventional Commits on `main`, grouped by component.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1-rc.5](https://github.com/r-gawronski/tagwarden/compare/v0.1.1-rc.4...v0.1.1-rc.5) (2026-11-13)

### Controller

#### Features

* per-mirror onTagMutation limited by the target ([#118](https://github.com/r-gawronski/tagwarden/pull/118)) ([3d1118d](https://github.com/r-gawronski/tagwarden/commit/3d1118d73435b0ff4fd716d00037ce3bee6038c1)), closes [#117](https://github.com/r-gawronski/tagwarden/issues/117)


## [0.1.1-rc.4](https://github.com/r-gawronski/tagwarden/compare/v0.1.1-rc.3...v0.1.1-rc.4) (2026-11-13)

### Controller

#### Features

* record VulnerabilityExceptionApplied Event ([#113](https://github.com/r-gawronski/tagwarden/pull/113)) ([c47bdee](https://github.com/r-gawronski/tagwarden/commit/c47bdee6512f137679c870b4725b5daee03a272e)), closes [#74](https://github.com/r-gawronski/tagwarden/issues/74)

#### Bug fixes

* read the sync pod from the API server when the cache has no result ([#115](https://github.com/r-gawronski/tagwarden/pull/115)) ([69b31a2](https://github.com/r-gawronski/tagwarden/commit/69b31a27f82a4b567459fa3584c9038cc40799b9))

### Other

#### Bug fixes

* use helm --wait=legacy to avoid kstatus watcher panic ([#112](https://github.com/r-gawronski/tagwarden/pull/112)) ([f7b85a9](https://github.com/r-gawronski/tagwarden/commit/f7b85a983d5b288dea85015d1edcb7fea0a538af)), closes [#83](https://github.com/r-gawronski/tagwarden/issues/83)


## [0.1.1-rc.3](https://github.com/r-gawronski/tagwarden/compare/v0.1.1-rc.2...v0.1.1-rc.3) (2026-11-12)

### Dependencies

#### Bug fixes

* bump Go to 1.26.11 (GO-2026-6859) ([#108](https://github.com/r-gawronski/tagwarden/pull/108)) ([4a6906c](https://github.com/r-gawronski/tagwarden/commit/4a6906c2476099a2324aae897d658d9feb2b5728))
* bump klauspost/compress to v1.20.2 (GO-2026-6865) ([#100](https://github.com/r-gawronski/tagwarden/pull/100)) ([6440ed5](https://github.com/r-gawronski/tagwarden/commit/6440ed5ba2f84064ad1bd0dd7561b945ed00e69f))

### Other

#### Bug fixes

* clearer sync summary in status ([#110](https://github.com/r-gawronski/tagwarden/pull/110)) ([7536839](https://github.com/r-gawronski/tagwarden/commit/7536839befeb094e4236916977a14471b03ab58a))
* raise message length caps and pass the target name to sync Jobs ([#109](https://github.com/r-gawronski/tagwarden/pull/109)) ([3356783](https://github.com/r-gawronski/tagwarden/commit/335678389e6669d9b67d99f7f0f4ca801b8f0fb9))
* requeue status update conflicts instead of logging Reconciler error ([#103](https://github.com/r-gawronski/tagwarden/pull/103)) ([bbf4d4f](https://github.com/r-gawronski/tagwarden/commit/bbf4d4f4a2f695c5a2629c37d6efc298edd17676)), closes [#102](https://github.com/r-gawronski/tagwarden/issues/102)

## [0.1.1-rc.2](https://github.com/r-gawronski/tagwarden/compare/v0.1.1-rc.1...v0.1.1-rc.2) (2026-11-05)

### Highlights

Opt-in prune: with `spec.tags.prune: true` a mirror deletes target tags it copied and no longer selects. Only tags in `status.owned` are pruned, never a digest; tags pushed before the upgrade are not adopted.

### Other

#### Features

* prune tags a mirror no longer selects ([#95](https://github.com/r-gawronski/tagwarden/pull/95)) ([5ee5f0d](https://github.com/r-gawronski/tagwarden/commit/5ee5f0d8b88ae954110c594c51652a44483a4da1))

## [0.1.1-rc.1](https://github.com/r-gawronski/tagwarden/compare/v0.1.0...v0.1.1-rc.1) (2026-11-05)

### Highlights

Harbor targets delete tags through the Harbor API. A ClusterMirrorTarget can set its own `maxListedTags` limit. Adds the SBOM design and the SBOM referrer package.

### API

#### Features

* configurable maxListedTags limit per ClusterMirrorTarget ([#87](https://github.com/r-gawronski/tagwarden/pull/87)) ([43dadee](https://github.com/r-gawronski/tagwarden/commit/43dadee806ec07d9d04bf9515ea395369aa1a1c5)), closes [#86](https://github.com/r-gawronski/tagwarden/issues/86)

### Sync

#### Bug fixes

* split auth checks out of Spec.validate ([#92](https://github.com/r-gawronski/tagwarden/pull/92)) ([6a458f2](https://github.com/r-gawronski/tagwarden/commit/6a458f24b020389679e4aaac0972dd5cb92b9bd7))

### SBOM

#### Features

* design and SBOM referrer package ([#69](https://github.com/r-gawronski/tagwarden/issues/69)) ([#85](https://github.com/r-gawronski/tagwarden/pull/85)) ([df374b0](https://github.com/r-gawronski/tagwarden/commit/df374b041588d90eb06c1d45fd4a5c548ed225df))

### Other

#### Features

* Harbor tag delete through the Harbor API ([#71](https://github.com/r-gawronski/tagwarden/issues/71)) ([#88](https://github.com/r-gawronski/tagwarden/pull/88)) ([d940f48](https://github.com/r-gawronski/tagwarden/commit/d940f48b8680784fcda9bd25af54cb676d7a9de1))

## [0.1.0](https://github.com/r-gawronski/tagwarden/compare/v0.1.0-rc.2...v0.1.0) (2026-11-05)

### Highlights

First stable release. Same code as 0.1.0-rc.2, promoted after it ran without problems. See the release candidates below for the full list of changes.

## [0.1.0-rc.2](https://github.com/r-gawronski/tagwarden/compare/v0.1.0-rc.1...v0.1.0-rc.2) (2026-11-04)

### Highlights

A sync that selects no tags is now a warning (`NoTagsSelected`) instead of a silent success. Release notes come from this changelog.

### Other

#### Bug fixes

* report an empty tag selection loudly ([#81](https://github.com/r-gawronski/tagwarden/pull/81)) ([754c8f3](https://github.com/r-gawronski/tagwarden/commit/754c8f3757901c2aa0ea82187f4875d6badd4532)), closes [#80](https://github.com/r-gawronski/tagwarden/issues/80)

## [0.1.0-rc.1] (2026-11-04)

### Highlights

First release candidate. Mirrors container images and Helm OCI charts with tag selection by regex, semver range and keep-latest. Reaches registries through an HTTP proxy and custom CA bundles. Isolates tenants with ClusterMirrorTarget projects and policy limits. Pulls with source credentials and authenticates to Azure Container Registry, Amazon ECR and Google Artifact Registry with workload identity. Mirrors images of annotated pods automatically. A vulnerability gate scans with Trivy, accepts VulnerabilityException objects, and re-scans mirrored tags to untag vulnerable ones. Images and charts are signed with cosign and carry an SBOM.

### Breaking changes

* **api:** `spec.platforms` of ArtifactMirror is renamed to `spec.requiredPlatforms`. Rename the field in existing ArtifactMirror objects before upgrading.

### API

#### Features

* add AWS IRSA and Amazon ECR registry auth to ClusterMirrorTarget ([5b98a7e](https://github.com/r-gawronski/tagwarden/commit/5b98a7ece0fcca8353f52c6e2cc5ab2c2e2d61b3))
* add ClusterMirrorTarget spec.limits ([7a8ae99](https://github.com/r-gawronski/tagwarden/commit/7a8ae993bf865e43e6c2bca5a9ccc3b43f1ef7fb))
* add GCP workload identity federation and Artifact Registry auth to ClusterMirrorTarget ([7504244](https://github.com/r-gawronski/tagwarden/commit/7504244af74bbd8386dc2b0b68e0523e16235cde))
* add allowRepositoryOverride to target projects ([169f38d](https://github.com/r-gawronski/tagwarden/commit/169f38d3628ec5acdec592cc3b7a7ff4f097f713))
* add autoMirror to ClusterMirrorTarget ([dc38ca0](https://github.com/r-gawronski/tagwarden/commit/dc38ca067cc6a1e3e37ce386f74d696f5f4deb97))
* add sourceCredentials and sourceCABundles to ClusterMirrorTarget ([cbc3219](https://github.com/r-gawronski/tagwarden/commit/cbc32198d7acbe7e8a0a8b92221cef128d29a6a2))
* add sync-now annotation and sync request status ([62621d9](https://github.com/r-gawronski/tagwarden/commit/62621d9b733a1da0fc31ee5be28d96b2aaaac097))
* add v1alpha1 types with CEL validation ([d3e0d81](https://github.com/r-gawronski/tagwarden/commit/d3e0d8108db120f142416e0fa1c90884853ce544))
* add workload identity and Azure registry auth to ClusterMirrorTarget ([dc07116](https://github.com/r-gawronski/tagwarden/commit/dc07116a3114188476bc0c2fb8394daa852b6fd4))
* per-project namespace access, stricter hosts, paths and schedules ([dd88597](https://github.com/r-gawronski/tagwarden/commit/dd88597b48e5208302c4b9c7bc1a75bb6231bcdf))
* rename platforms to requiredPlatforms ([bc59f43](https://github.com/r-gawronski/tagwarden/commit/bc59f43d3539401b8e933cf2e92ccbb068ec0ce1))

### Controller

#### Features

* cap mirrors per namespace, keepLatest and explicit tags ([c6ff61d](https://github.com/r-gawronski/tagwarden/commit/c6ff61d73d938373e40520fe2d539f99e7b0442d))
* label sync pods with target and egress mode ([6c8cb6e](https://github.com/r-gawronski/tagwarden/commit/6c8cb6e277b72a28ca611ee1b75493ad502fa480))
* mirror images of annotated pods ([70fe897](https://github.com/r-gawronski/tagwarden/commit/70fe8977a4d9b45c3ef91c269eeffcf3c0b3d46b))
* mount only the source Secrets of a mirror's registry ([4ed52a6](https://github.com/r-gawronski/tagwarden/commit/4ed52a6d9f5b0d64c6451d6977a86ea78f9878ff))
* parse pod image refs for auto-mirror ([5d82ae2](https://github.com/r-gawronski/tagwarden/commit/5d82ae23d73c14f8b1569039fe46bac12f90447c))
* probe the Trivy server for scanner readiness ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#55](https://github.com/r-gawronski/tagwarden/pull/55)) ([a1a5413](https://github.com/r-gawronski/tagwarden/commit/a1a5413281bead15a24db0299112dde478136469))
* readable names for generated CronJobs and ConfigMaps ([#40](https://github.com/r-gawronski/tagwarden/pull/40)) ([1e87439](https://github.com/r-gawronski/tagwarden/commit/1e8743900f222f6c09c200d8385614ce44c43006))
* record gate results in status and relay them to pods ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#59](https://github.com/r-gawronski/tagwarden/pull/59)) ([257b7a0](https://github.com/r-gawronski/tagwarden/commit/257b7a0b54ee59e6db3f1e0dd8ace06f2782b024))
* refuse schedules below minSyncInterval ([11353dd](https://github.com/r-gawronski/tagwarden/commit/11353dde8b273147a991625468d896b6a012f6ba))
* render each ArtifactMirror into a hardened CronJob ([9656610](https://github.com/r-gawronski/tagwarden/commit/9656610d7a16eb2a810053261e34aff9e2f95a2f))
* render the Trivy sidecar for gated sync Jobs ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#57](https://github.com/r-gawronski/tagwarden/pull/57)) ([a822946](https://github.com/r-gawronski/tagwarden/commit/a8229468930438d5932aba118b836cfd99dc476b))
* report ClusterMirrorTarget Secret readiness ([ce5226c](https://github.com/r-gawronski/tagwarden/commit/ce5226ce9fb0acec2eef4b44256c1166bbab31bf))
* report sync results from finished Jobs ([a2662af](https://github.com/r-gawronski/tagwarden/commit/a2662af8d996b54e448a6a30fd3fbe9e667abd8f))
* run AWS-auth sync pods with a projected STS-audience token ([039144a](https://github.com/r-gawronski/tagwarden/commit/039144ade0b96b51a04bc3f0a1ea37ac80857bb6))
* run Azure-auth sync pods with a projected workload identity token ([aaefe8f](https://github.com/r-gawronski/tagwarden/commit/aaefe8f39e1e9a1a78edf349d9a94826df20e0d7))
* run GCP-auth sync pods with a projected provider-audience token ([96a9337](https://github.com/r-gawronski/tagwarden/commit/96a933790e021b28e22451a66cb9d6891519b742))
* show sync CronJobs under the mirror's Argo CD app ([ee4e944](https://github.com/r-gawronski/tagwarden/commit/ee4e94411360ea92673bf334b9dacff568dc5e53))
* start a sync Job for each new sync-now request ([a1db0a0](https://github.com/r-gawronski/tagwarden/commit/a1db0a04b90192b8d3185879984de710701be324))
* validate source credential and CA Secrets of a target ([81bf41c](https://github.com/r-gawronski/tagwarden/commit/81bf41c53ba24791f0d86cf4b51d006cd14c77e9))

#### Bug fixes

* check schedule gaps over five years ([4a3d3f5](https://github.com/r-gawronski/tagwarden/commit/4a3d3f5b2d511ec5867d9b659e88518c65fa5c39))
* compare host, DNS and scheduling fields of sync pods ([c3e56da](https://github.com/r-gawronski/tagwarden/commit/c3e56dad7111e83bdd7ac76e882c285449af7de6))
* guard foreign objects and re-check shared target paths ([0f5e14f](https://github.com/r-gawronski/tagwarden/commit/0f5e14f9ef75665734afd4a9f525f84118422278))
* harden auto-mirror against bad images, drift and name clashes ([b28a5af](https://github.com/r-gawronski/tagwarden/commit/b28a5aff4f00645d91c239d151058743677f486a))
* keep the LimitExceeded message stable for mirror counts ([ebd850b](https://github.com/r-gawronski/tagwarden/commit/ebd850bbc34dfcbaf77f50b77baadff488fa2dcf))
* make the CronJob the controller of manual sync Jobs ([33686ed](https://github.com/r-gawronski/tagwarden/commit/33686ed2920e8d2360c571e934a449651d21a522))
* read Jobs past the cache when handling sync requests ([6dc88bc](https://github.com/r-gawronski/tagwarden/commit/6dc88bcaa7c872efc50143b59cc4ebfa51002fca))
* refuse a sync-now value whose Job already finished ([78f8f2b](https://github.com/r-gawronski/tagwarden/commit/78f8f2b91abd06dbc19b4a68a86b67bafabcae2e))
* refuse target repository overrides in shared projects ([59c0224](https://github.com/r-gawronski/tagwarden/commit/59c0224a725b9659f5881c764b6cb56172ecaceb))
* refuse targets whose allowedSources share a path segment ([25c2c6a](https://github.com/r-gawronski/tagwarden/commit/25c2c6a0663600c950a80e2f179cdcee6b674744))
* restore hand-edited security fields of sync CronJobs ([48cdfac](https://github.com/r-gawronski/tagwarden/commit/48cdfac4fe454c9ebc3b9a67e1cfc863aee35d20))
* restore only tagwarden.dev pod labels ([79274a0](https://github.com/r-gawronski/tagwarden/commit/79274a0cef93c71250febe55eba751650ba56324))
* set SYNC_IMAGE from the final manager image in config/default ([f1eb014](https://github.com/r-gawronski/tagwarden/commit/f1eb0146fd990e3eb952a310e58013f859e991d3))

#### Performance

* cache schedule gap checks ([#33](https://github.com/r-gawronski/tagwarden/pull/33)) ([b574050](https://github.com/r-gawronski/tagwarden/commit/b57405067262c1092bf717bffb970b6918859175))
* re-check namespace mirror counts only when they can change ([29e5552](https://github.com/r-gawronski/tagwarden/commit/29e5552a3490dd2d0d58db5073131c380918d1dd))

### Sync

#### Features

* add spec contract between controller and sync job ([7f7670e](https://github.com/r-gawronski/tagwarden/commit/7f7670ec7aeb8174b7dcbcfea94e7b001ff96257))
* authenticate to Amazon ECR with IRSA ([d673f25](https://github.com/r-gawronski/tagwarden/commit/d673f25a8bbd8aef2563a0eb5236da52b93756fb))
* authenticate to Azure Container Registry with workload identity ([7a8ac22](https://github.com/r-gawronski/tagwarden/commit/7a8ac22180a3e132bcd5d31b8da17df5a409e881))
* authenticate to Google Artifact Registry with workload identity federation ([514bf8b](https://github.com/r-gawronski/tagwarden/commit/514bf8b674062c71cb288b089e6c3e07c51c34fe))
* copy selected tags by digest with referrers and mutation policy ([e8940f6](https://github.com/r-gawronski/tagwarden/commit/e8940f6d1eb9ce297c77c1ea6c2279bedaf95ae4))
* pull with source credentials and trust a per-source CA ([7486d60](https://github.com/r-gawronski/tagwarden/commit/7486d60f8613d0ba35e3ac3781575212566a7cfe))
* record per-artifact audit details ([5761eb0](https://github.com/r-gawronski/tagwarden/commit/5761eb0100564eb62a15daf4d8957457a65484bd))
* refuse artifacts larger than maxArtifactSize ([34ef2bd](https://github.com/r-gawronski/tagwarden/commit/34ef2bda9fce3bacb916900624fa2e6c1a83d967))
* report the selected tags in order ([c30e2a4](https://github.com/r-gawronski/tagwarden/commit/c30e2a463e137b4c56a782e0f55b8a0bf3c5ecfb))
* scan gated tags through the Trivy sidecar before copying ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#56](https://github.com/r-gawronski/tagwarden/pull/56)) ([5c35140](https://github.com/r-gawronski/tagwarden/commit/5c351409fc2436133c676870c01eace23f37c91a))
* sync referrers of up-to-date tags ([baa3fec](https://github.com/r-gawronski/tagwarden/commit/baa3fec11a7a09ea7e2c62c84e0d2502e18e4ad7))

#### Bug fixes

* cap referrers of an artifact at maxArtifactSize ([3a264b2](https://github.com/r-gawronski/tagwarden/commit/3a264b26144fe2841bd458e1a9249a0ae9ca91dd))
* check target before fetching referrers of up-to-date tags ([ed5dcfa](https://github.com/r-gawronski/tagwarden/commit/ed5dcfa4812d7faac0d8dd3bb7aa7afaeeaf3bc4))
* drop the default port from the ACR token exchange host ([31bd745](https://github.com/r-gawronski/tagwarden/commit/31bd7453fe183f54700cfd97f1f68f2168fbdf31))
* fall back to GET when HEAD gives no digest ([938a642](https://github.com/r-gawronski/tagwarden/commit/938a6424800da210878602928a344a053131fe10))
* fold only ASCII letters when matching ACR hosts ([d6e2b07](https://github.com/r-gawronski/tagwarden/commit/d6e2b0752c56c99fe67029c69dc571d60c7bb404))
* keep Google access tokens on the registry host and narrow the impersonated scope ([deba708](https://github.com/r-gawronski/tagwarden/commit/deba7081edbf2795b415dbd520e26247be00dcb3))
* never turn a registry error on HEAD into a GET ([e98bd60](https://github.com/r-gawronski/tagwarden/commit/e98bd6053643951860d8bb00aaca6feb4ca28673))
* report an overwritten tag as mutated only after the copy ([a810b48](https://github.com/r-gawronski/tagwarden/commit/a810b48761639b157f391cd80d21786b953ba166))
* report the target digest of an ignored mutated tag ([a1d73fd](https://github.com/r-gawronski/tagwarden/commit/a1d73fd03d18ae8a2c44b69a1099113c1e70a34c))
* request one-hour STS sessions for ECR tokens and expand IRSA docs ([8c2eefe](https://github.com/r-gawronski/tagwarden/commit/8c2eefe2da8ec421927ea6f13e46b70f397991ae))
* resolve explicit-only tags without listing the source ([#62](https://github.com/r-gawronski/tagwarden/pull/62)) ([8358243](https://github.com/r-gawronski/tagwarden/commit/83582439144cd1a9932a4682a1b6597e67c9d163))
* rune-safe messages, fixed page cap and review comments ([c02d665](https://github.com/r-gawronski/tagwarden/commit/c02d6658f3867cf756cd8c56e3ce86d74a0f70a4))
* treat arm64 and arm64/v8 as the same platform ([929c6ef](https://github.com/r-gawronski/tagwarden/commit/929c6ef6665c10d73569dc215d84e88c48ee22b3))

### Tags

#### Features

* add tag selection with regex, semver range and keep latest ([34a17e5](https://github.com/r-gawronski/tagwarden/commit/34a17e50e3f349f44a67aaf378b803c5fe670a08))

#### Bug fixes

* reject leading zeros and clarify prerelease opt-in ([0e556c7](https://github.com/r-gawronski/tagwarden/commit/0e556c779bf4fc8338fe945d83afa275c4a07e72))
* strict semver tags, prerelease opt-in, explicit tags and program size cap ([4e9ba71](https://github.com/r-gawronski/tagwarden/commit/4e9ba71450a3a93aae8e4a74bea76e743194ad49))

### Registry

#### Features

* add host and dial checks to the transport ([7290bc9](https://github.com/r-gawronski/tagwarden/commit/7290bc9ba08adc4f666cdb28ccf96e8125b1762f))
* add transport with proxy, custom CA and mTLS ([a0a741a](https://github.com/r-gawronski/tagwarden/commit/a0a741a719ff4fd055eacd95199b50261e51b383))

#### Bug fixes

* retry connection errors while network policy settles ([039512c](https://github.com/r-gawronski/tagwarden/commit/039512c1a3e9f665f0fb92f7bb87f0f647898851))
* retry only during a shared startup window ([22ed7b2](https://github.com/r-gawronski/tagwarden/commit/22ed7b24406a22165e5d02065cb397cd429b4646))

### Vulnerability gate

#### Features

* report parser and verdicts for the vulnerability gate ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#53](https://github.com/r-gawronski/tagwarden/pull/53)) ([5d0a6bf](https://github.com/r-gawronski/tagwarden/commit/5d0a6bfa6e8bdc39cb82e05541018de3c77c5441))

#### Bug fixes

* fail fast and loud when the scanner sidecar does not start ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#63](https://github.com/r-gawronski/tagwarden/pull/63)) ([9a0049d](https://github.com/r-gawronski/tagwarden/commit/9a0049dd0b7e61dcab250a1bab5ff370b1641316))

### CLI

#### Features

* add sync subcommand with termination-log result and audit log ([331a04e](https://github.com/r-gawronski/tagwarden/commit/331a04e405ba9f1ec388307d930c19da92f01916))
* check every source request, redirect and connection ([8406b18](https://github.com/r-gawronski/tagwarden/commit/8406b1832032e1f57a9ea50a7caade559bab245a))
* check the source registry before any network call ([5703e1c](https://github.com/r-gawronski/tagwarden/commit/5703e1c5ed1fa2a28ce12e684ca1e9760b041226))

#### Bug fixes

* deterministic auth choice and clearer audit lines ([d9e776c](https://github.com/r-gawronski/tagwarden/commit/d9e776c2e1ba869d0eba25b7f206758e3a5abe9b))
* exit 3 on config errors and 1 on panics and transient errors ([9f0b3d9](https://github.com/r-gawronski/tagwarden/commit/9f0b3d909a616c82767c6a6050e89bc532dfeaee))
* ignore env proxy, cache lookups and document crash exit code ([0fc80a1](https://github.com/r-gawronski/tagwarden/commit/0fc80a1590129b5b8e2fc9b19a417f714dc9f0ba))
* keep the first errors when truncating the termination message ([54ad94b](https://github.com/r-gawronski/tagwarden/commit/54ad94b4ccdab68bf7dac52efab1d849a7265a13))
* retry temporary DNS errors while network policy settles ([66e556e](https://github.com/r-gawronski/tagwarden/commit/66e556e576920c27acd4b2a6f3c1fa471be657b1))

### Chart

#### Features

* add argocd.tracking and argocd.instanceLabel values ([3dc4266](https://github.com/r-gawronski/tagwarden/commit/3dc42661393c57c28f06a878f3cc10ea74af8171))
* add schema, image digests, sync image, denied CIDRs and mirrors ([5008a9b](https://github.com/r-gawronski/tagwarden/commit/5008a9bc3d28044f88f5b4f6d08a93f1c4709c45))
* add the in-chart Trivy server for the vulnerability gate ([#52](https://github.com/r-gawronski/tagwarden/pull/52)) ([de56736](https://github.com/r-gawronski/tagwarden/commit/de5673686365f85bc1b11cd408c797cffb077175))
* allow manager pod annotations and labels ([074ec04](https://github.com/r-gawronski/tagwarden/commit/074ec0497c64b4eafe40e7bf2b3bf57a07451a9c))

#### Bug fixes

* default the sync image tag to the manager image tag ([2abbc40](https://github.com/r-gawronski/tagwarden/commit/2abbc407b9efe8225027031d8cdf19d06f53f26a))
* keep chart-managed targets and mirrors on uninstall ([fdd307d](https://github.com/r-gawronski/tagwarden/commit/fdd307d4338ba95ea95b95c37b80182ae177f7f5))
* require the sync image and denied CIDR flags in manager.args ([6ee2b07](https://github.com/r-gawronski/tagwarden/commit/6ee2b0798c57afa93f2570eaaeb96aa2989a6113))

### Dependencies

#### Bug fixes

* bump google.golang.org/grpc to v1.83.2 (CVE-2026-84445) ([d5be2ea](https://github.com/r-gawronski/tagwarden/commit/d5be2ea7eca3fc6d38cad0a45aeb1ef36dbfd0c3))

### Other

#### Features

* re-scan mirrored tags of gated mirrors and untag vulnerable ones ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#65](https://github.com/r-gawronski/tagwarden/pull/65)) ([0ed4e61](https://github.com/r-gawronski/tagwarden/commit/0ed4e61442da08326177e2050b029220cc730966))
* vulnerability gate API and VulnerabilityException ([#21](https://github.com/r-gawronski/tagwarden/issues/21)) ([#54](https://github.com/r-gawronski/tagwarden/pull/54)) ([ccb5c3f](https://github.com/r-gawronski/tagwarden/commit/ccb5c3f25f2312c18b755c00e783092bfb722e31))
* wire the controllers with operator namespace, sync image and RBAC ([561c8dd](https://github.com/r-gawronski/tagwarden/commit/561c8dd5a82fde6400ef56e036d76844218b15d0))

#### Bug fixes

* limit Azure workload identity to ACR hosts, known authorities and the ACR scope ([0923260](https://github.com/r-gawronski/tagwarden/commit/09232609c63dca3d7aac4d296cebe0ff06ec3a98))
