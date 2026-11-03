# Phase 0 spike results

Status: spikes 1, 2 and 3 finished. Vulnerability gate spike (#21) finished, see the last section.

## Environment

- macOS arm64, Docker 27.5.1, Go 1.27.3
- go-containerregistry v0.22.1
- cosign v3.1.4, helm v4.1.4
- TLS-inspecting proxy: mitmproxy 11.1.3 in Docker, regular mode, with a throwaway CA.
  - Squid not used: the `ubuntu/squid` image has no OpenSSL build, so no ssl_bump.
  - mitmproxy 12.3.1 (latest arm64 image) exits with SIGILL (code 132) on Docker Desktop arm64. 11.1.3 works.
- zot: latest image, distSpecVersion 1.1.1, TLS from a throwaway CA, port 5443.
- Harbor 2.15.4 with a publicly trusted certificate, temporary project (deleted afterwards).

Spike code is not part of this repository. It had a transport package `tr` and three programs: `cmd/proxy` (spike 1), `cmd/copy` (spikes 2 and 3a) and `cmd/helmpush` (spike 3b).

## Spike 1: proxy + TLS inspection -- WORKS

Transport: clone of `http.DefaultTransport`, `Proxy = http.ProxyFromEnvironment`,
`RootCAs = SystemCertPool() + extra PEM files`, `MinVersion = TLS1.2`.

| Check | Result |
|---|---|
| (a) with proxy CA: `remote.List`, `remote.Get` (index), layer pull of registry.k8s.io/pause:3.10 | works, 33 tags, 7-entry index, layer downloaded |
| (b) without proxy CA | fails: `tls: failed to verify certificate: x509: "registry.k8s.io" certificate is not trusted` |
| (c) NO_PROXY bypass to zot | works. Without NO_PROXY the request went through the proxy and got `502 Bad Gateway` (proxy does not trust the zot CA). With NO_PROXY set, zero zot requests in the proxy log. |
| (d) proxy log shows requests | yes, every request URL and status is logged |

Caveat for (c): Go's `ProxyFromEnvironment` always bypasses the proxy for
`localhost` and `127.0.0.1`, whatever NO_PROXY says. The NO_PROXY test used the host LAN IP
(added to the zot certificate SANs) to prove the env var really takes effect.

### Upstream hosts seen by the proxy

A proxy with a host allowlist must allow all of these. Blob downloads are redirected.

| Source | API host | Redirect / blob hosts |
|---|---|---|
| registry.k8s.io | registry.k8s.io | `<region>-docker.pkg.dev` (manifests and tags/list, 307; seen: europe-west10), `cdn.registry.k8s.io` (blobs, 307) |
| ghcr.io | ghcr.io | pkg-containers.githubusercontent.com (blobs) |
| Docker Hub (docker.io) | index.docker.io, auth.docker.io | production.cloudfront.docker.com (blobs) |
| quay.io | quay.io | cdn01.quay.io (blobs) |

Notes:
- registry.k8s.io picks the redirect target by client location. The pkg.dev region and blob CDN can differ per site. Allowlist `*.pkg.dev` and `cdn.registry.k8s.io`, or test from the target site.
- Redirects also apply to manifests and tag lists on registry.k8s.io, not only blobs.
- ggcr normalises `docker.io` to `index.docker.io`. Helm and other clients use `registry-1.docker.io`. Allow both.
- quay.io CDN host numbering (cdn01, cdn02...) may vary.

## Spike 2: index + signatures + referrers copy -- WORKS

Program `cmd/copy`: `remote.Get` the source, write by digest (`WriteIndex` / `Write`),
then for the index and every child: probe `sha256-<hex>.sig|.att|.sbom` tags and
`remote.Referrers`, copy each by digest, re-tag tag-scheme artifacts. After each write it
does `remote.Head` on the target and asserts the digest is unchanged.

Images:
- ghcr.io/sigstore/cosign/cosign:v3.1.4 -- signed only via OCI 1.1 referrers
  (artifactType `application/vnd.dev.sigstore.bundle.v0.3+json`), 2 on the index, 2 on each of 6 platform manifests. No `.sig` tags.
- ghcr.io/sigstore/cosign/cosign:v2.5.0 -- tag scheme only: `.sig` and `.sbom` tags on the index and on each platform manifest.

| Check | zot | Harbor 2.15.4 |
|---|---|---|
| Index with all platforms copied | yes | yes |
| Digests identical after `Write` / `WriteIndex` | yes, all 15 (v3.1.4) and 18 (v2.5.0) manifests | yes, same |
| `.sig` / `.sbom` tag scheme copied | yes | yes |
| OCI 1.1 referrers (subject field) accepted | yes | yes |
| `/v2/<name>/referrers/<digest>` lists them | yes | yes, also honours `?artifactType=` (`OCI-Filters-Applied: artifactType`) |
| Fallback `sha256-<hex>` referrers tags created at target | no (native API used) | no |
| `cosign verify` v3.1.4 (bundle referrers) | pass | pass |
| `cosign verify` v2.5.0 (`.sig` tag) | pass | pass |

Verify flags that work for sigstore's own cosign images:
`--certificate-identity=keyless@projectsigstore.iam.gserviceaccount.com --certificate-oidc-issuer=https://accounts.google.com`.
The GitHub workflow identity (`https://github.com/sigstore/cosign/.github/workflows/release.yml@refs/tags/...` with issuer `token.actions.githubusercontent.com`) does NOT match; the container images are signed from Google Cloud Build.
For zot with a private CA, cosign needs `--registry-cacert`.

Harbor behaviour:
- Referrer bundles and `.sig` tags both show up as `signature.cosign` accessories of the subject artifact.
- `.sbom` tag-scheme artifacts are NOT treated as accessories. They appear as separate top-level artifacts in the repository.

Caveats:
1. ghcr.io has no referrers API (`/v2/.../referrers/<digest>` returns 404). ggcr falls back to the `sha256-<hex>` tag.
2. That fallback is unsafe. On ghcr, cosign v2.5.0 has a tag `sha256-<index digest>` that points to the image index itself. ggcr `remote.Referrers` returned the 6 platform manifests as "referrers" (empty artifactType, no subject). The sync engine must check that each returned descriptor's manifest has `subject.digest == <target digest>` and drop the rest.
3. cosign verification still needs the sigstore trust root (TUF) and, by default, Rekor/Fulcio. Offline or air-gapped verification needs a pre-fetched trusted root. Not tested here.
4. `remote.Write` / `WriteIndex` keep the original manifest bytes, so digests are preserved. Do not decode and re-encode manifests anywhere in the pipeline.

## Spike 3: Helm -- WORKS

Program `cmd/helmpush`: ggcr only, no Helm SDK. Reads `<chart>.tgz` and `<chart>.tgz.prov`,
builds config (Chart.yaml as JSON), chart layer and provenance layer, writes blobs with
`remote.WriteLayer` and the manifest bytes with `remote.Put`. `tr/tr.go` was recreated from the
spike 1 description (the original was lost with the temp module).

### (a) OCI chart copy: ghcr.io/stefanprodan/charts/podinfo:6.17.0 -> Harbor 2.15.4

| Check | Result |
|---|---|
| `cmd/copy` by digest, then tag | works, no code change needed |
| Manifest digest source = target | yes, `sha256:258d0da545724b4eea8de5d5e724cd9a75aab3de79a87ba8d82ec402745cea58` |
| `helm pull oci://<harbor>/<project>/podinfo --version 6.17.0` | works, same `Digest:` line, `.tgz` sha256 identical to a pull from ghcr |
| Harbor artifact type | `CHART` (config media type `application/vnd.cncf.helm.config.v1+json`) |
| Signatures | 2 OCI 1.1 referrers, both with `subject` = chart digest: a cosign bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`) and a Notation signature (config `application/vnd.cncf.notary.signature`, layer `application/cose`). No `.sig` tag. Both copied with identical digests. |
| Harbor accessories | `signature.cosign` and `signature.notation` on the chart |
| `cosign verify` on the Harbor copy | pass (`--certificate-identity-regexp '^https://github.com/stefanprodan/podinfo/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`) |

Notes:
- The podinfo chart manifest has no `mediaType` field. ggcr takes the type from the
  `Content-Type` header and keeps the raw bytes, so the digest is preserved.
- An OCI chart is just an OCI manifest. The image sync path covers it. Notation signatures
  ride along through the referrers copy; they are not cosign-specific.

### (b) Classic repo with provenance

| Repo | `.prov` next to `.tgz` | Public key |
|---|---|---|
| https://charts.jetstack.io | yes (cert-manager v1.21.3) | yes, URL in the `artifacthub.io/signKey` chart annotation (binary keyring on cert-manager.io) |
| https://prometheus-community.github.io/helm-charts | yes (alertmanager 2.1.4) | no `signKey` annotation, not tested |
| https://helm.cilium.io | no (404) | - |
| https://kubernetes.github.io/ingress-nginx | no (404) | - |

`index.yaml` never lists `.prov` files. The convention is `<chart url>.prov`; probe it with a HEAD/GET and treat 404 as unsigned.

Test chart: cert-manager v1.21.3 from charts.jetstack.io, key fingerprint `1020CF3C033D4F35BAE1C19E1226061C665DF13E`.
Chart `.tgz` sha256: `9ec67938b2981d8b333af61b3fcf53e26b4f6f5deb7ccda3de4ea116bb373a17`.

| Check | `helm push` (CLI 4.1.4) | `cmd/helmpush` (ggcr) |
|---|---|---|
| Local `helm verify --keyring` before push | pass | pass |
| `.prov` pushed | yes, automatically when `<chart>.tgz.prov` sits next to the `.tgz`. No flag. | yes |
| Layer order | sorted by digest (prov first here) | chart, then prov |
| Config blob | `json.Marshal(chart.Metadata)`: Go struct field order, HTML-escaped (`\u003e`) | `yaml.YAMLToJSON(Chart.yaml)`: sorted keys |
| Manifest annotations | 10: OCI title/version/description/url/source/authors/created plus chart annotations | none |
| Manifest digest | `sha256:09241c1e694e...` | `sha256:e0c6d8d6798c...` |
| Harbor type | `CHART` | `CHART` |
| `helm pull --verify --keyring` | pass, `Chart Hash Verified` | pass, `Chart Hash Verified` |

Digests: NOT equal. Both carry the identical chart and prov blobs; the config blob and the
manifest annotations differ. Provenance survives both ways because it signs the `.tgz` bytes,
not the OCI manifest.

Caveats:
1. `helm push` is not reproducible across machines. `org.opencontainers.image.created` is the
   local file mtime of the `.tgz`, formatted in the local time zone. Same file, same mtime: same
   digest (pushed twice, identical). `touch` to another date: new digest. Same file with `TZ=UTC`:
   new digest. The SDK (`registry.Client.Push`) uses `time.Now()` unless `PushOptCreationTime` is set.
2. So two mirrors of the same classic chart get different OCI digests. Any digest pinning on
   mirrored classic charts must come from our own deterministic build, not from "what helm push gives".
3. `helm pull --verify` with a wrong or empty keyring fails (`openpgp: signature made by unknown entity`,
   exit 1) but still leaves the `.tgz` and `.prov` on disk. Do not treat file presence as success.
4. `helm pull -d <dir>` fails if `<dir>` does not exist.
5. `helm registry login` writes to the OS credential store when a docker `credsStore` is
   configured, even with `HELM_REGISTRY_CONFIG` pointing elsewhere. Log out after tests.

Simplicity for the operator:
- Hand-built ggcr: about 60 lines of logic, one extra module (`sigs.k8s.io/yaml`), binary 11 MB,
  64 non-stdlib packages. Same transport and auth as the image path.
- Helm SDK `helm.sh/helm/v4/pkg/registry`: one `Push(data, ref, PushOptProvData, PushOptCreationTime)`
  call, but it pulls ORAS and its own auth/transport stack: binary 34 MB, 429 non-stdlib packages,
  and a second HTTP client to configure for proxy and CA.

### (c) Download hosts for proxy allowlists

| Repo | index.yaml host | Chart / prov host |
|---|---|---|
| charts.jetstack.io | charts.jetstack.io | same, no redirect |
| helm.cilium.io | helm.cilium.io | same, no redirect |
| ingress-nginx | kubernetes.github.io | github.com -> release-assets.githubusercontent.com (302) |
| prometheus-community | prometheus-community.github.io | github.com -> release-assets.githubusercontent.com (302) |

Notes:
- GitHub release downloads now redirect to `release-assets.githubusercontent.com`, not
  `objects.githubusercontent.com`. Allow both; older docs list the latter.
- Chart URLs in `index.yaml` can be relative (jetstack, cilium) or absolute on another host
  (GitHub releases). Resolve relative URLs against the index URL.
- The redirect targets are signed, short-lived URLs (`se=` expiry about one hour). Do not cache them.

## Recommendations

Task 1.3 transport:
- Use the transport as spiked: DefaultTransport clone, `ProxyFromEnvironment`, system pool + user CA bundle, TLS 1.2 minimum. It works through a TLS-inspecting proxy.
- Document that `localhost`/`127.0.0.1` always bypass the proxy (Go behaviour).
- Surface x509 errors verbatim with a hint to configure the proxy CA. That is the most likely first failure.
- Ship a per-source host allowlist table in the docs (table above). Redirect hosts are mandatory, not optional.

Task 1.4 sync engine:
- Copy by digest with `remote.Write` / `remote.WriteIndex`. Then `remote.Head` the target and fail on digest mismatch. Cheap, and it caught nothing here, which is the point.
- `WriteIndex` copies children recursively. Tag after the digest write, never before.
- Treat `remote.Referrers` output as untrusted: keep only descriptors whose manifest `subject` equals the target digest.

Phase 3 signatures:
- Copy both schemes: `sha256-<hex>.sig|.att|.sbom` tags and OCI 1.1 referrers, for the index and every child manifest. Current cosign (v3) uses referrers only; older releases use tags only.
- Harbor 2.15.4 and zot both serve the referrers API natively. No fallback tags are needed at the target.
- Do not hardcode signer identities from project docs. Read them from the certificate once (as done here) and configure them per source.
- Plan for an offline sigstore trusted root if verification runs inside the air-gapped cluster.

Phase 2 Helm:
- OCI chart sources: reuse the image sync path unchanged (copy by digest, then tag, plus referrers). No Helm-specific code.
- Classic repo sources: build the OCI artifact with ggcr (`cmd/helmpush` pattern), not the Helm SDK. One transport, one auth path, a third of the binary size.
- Make the build deterministic: fixed layer order, config bytes derived only from Chart.yaml, no `created` annotation (or one taken from the index.yaml `created` field). Then every mirror produces the same digest and re-syncs are no-ops.
- Expect digests to differ from a manual `helm push` of the same chart. Document it; compare on chart `.tgz` digest when matching against charts pushed by other tools.
- Fetch `<chart url>.prov` for every version; 404 means unsigned. Push it as the provenance layer. Optionally verify it before push with a per-source keyring (`helm verify` semantics: OpenPGP, binary or armored keyring).
- Add `release-assets.githubusercontent.com` and `objects.githubusercontent.com` to the allowlist table for GitHub-hosted classic repos.

## Vulnerability gate: Trivy client/server -- WORKS, with caveats

Step 0 of `docs/design/vulnerability-gate.md` (#21), run 2026-11-03.

Environment: Docker 27.5.1, linux/arm64 VM (8 GiB, 10 CPUs). One scan repeated
as linux/amd64 under emulation gave the same output. A throwaway CA, `registry:2`
with TLS and htpasswd (separate push and pull accounts) as the platform mirror,
`trivy-db:2` and `trivy-java-db:1` copied in with `crane copy`. Clients ran on an
internal Docker network that could reach only the Trivy server. Timings are
local-network numbers, so DB downloads are optimistic.

Pinned image: `ghcr.io/aquasecurity/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c`
(index, version 0.76.1, 4 platforms plus 4 attestation manifests, `USER` empty,
entrypoint `trivy`).

### Server

Worked as uid 65532, read-only root FS, all capabilities dropped,
no-new-privileges:

    trivy server --listen 0.0.0.0:4954 --cache-dir /cache \
      --token-header Trivy-Token \
      --db-repository registry.example.internal/platform/ghcr.io/aquasecurity/trivy-db:2
    # env: TRIVY_TOKEN, SSL_CERT_FILE=/ca.crt, DOCKER_CONFIG=/dockercfg,
    #      HOME=/tmp, TMPDIR=/tmp

| Check | Result |
|---|---|
| `--listen` | required; default is `localhost:4954` |
| DB pull from a private registry | works with a docker config (`{"auths":{"<host>":{"auth":"<base64>"}}}`) or `TRIVY_USERNAME`/`TRIVY_PASSWORD`; CA via `SSL_CERT_FILE`. DB pull 6 s. |
| Wrong password or missing CA | FATAL `failed to download vulnerability DB`, server exits |
| `--cache-dir` | `db/trivy.db` 1,690,918,912 B, `fanal/fanal.db` 3 MiB after ~10 images. Must be owned by 65532 (`fsGroup`), else `mkdir /cache/fanal: permission denied` |
| `/tmp` | holds the DB tarball during download. 256 MiB tmpfs failed (`no space left on device`); peak seen 265 MiB. Read-only: `failed to create a temp dir` |
| DB refresh (source, v0.76.1) | hourly ticker; downloads when `now > NextUpdate` (24 h after `UpdatedAt`) and the last download is over 1 h old. Swap waits for running requests. A failed refresh logs and keeps the old DB. Not observed live. |
| TLS | none. `trivy server` has no TLS flags; it serves plain HTTP. |

Memory:

| State | Value |
|---|---|
| idle | ~83 MiB, RSS ~106 MB after restart |
| after an alpine, nginx, JVM or tomcat scan | VmHWM 110 to 151 MB |
| after a python image (13,642 findings) | VmHWM 373 MB, cgroup peak 205 MiB |

The DB is memory-mapped, so most of it is page cache.

### Client

Worked as uid 65532, read-only root FS, layout mounted read-only, no upstream
network:

    trivy image --server http://<server>:4954 \
      --input /work/<layout>@sha256:<manifest digest> \
      --scanners vuln --format json \
      --skip-version-check --disable-telemetry --skip-java-db-update \
      --skip-files '**/*.jar,**/*.war,**/*.ear,**/*.par'
    # env: TRIVY_TOKEN, TMPDIR=<writable dir>; https: --cacert or SSL_CERT_FILE

- No DB download in server mode; the cache dir stays empty. Only a writable
  `TMPDIR` is needed (a 1 MiB tmpfs was enough for a 419 MiB image). Without
  it: FATAL `failed to create a cache layers temp dir`.
- Wire: Twirp over HTTP, protobuf, header `Trivy-Token`. `PutBlob` carries
  per-layer analysis (OS, package records, history lines, diff IDs), no file
  content. `Scan` carries the `--input` string, so the layout path reaches the
  server. Sent: python 419 MiB layout 1.55 MB, tomcat 0.64 MB, nginx 0.24 MB.
- Wrong token: exit 1, `twirp error unauthenticated: invalid token`. Exit 0 with
  findings, 1 on any error. Stdout is clean JSON, progress on stderr.
- UNKNOWN is `"Severity": "UNKNOWN"`. The Debian DLA entries checked had no
  `SeveritySource`.
- An EOSL OS is flagged (`Metadata.OS.EOSL: true`); the scan still succeeds.

### Java DB

JAR detection runs on the client. The server has no Java DB.

| Mode | Result |
|---|---|
| no flags, no upstream | tries `mirror.gcr.io/aquasec/trivy-java-db:1`, FATAL |
| `--skip-java-db-update`, no Java DB | FATAL `The first run cannot skip downloading Java DB` on any image with a JAR, WAR, EAR or PAR, including nginx (`libintl.jar` from gettext). `--offline-scan` does not help. |
| plus `--skip-files '**/*.jar,**/*.war,**/*.ear,**/*.par'` | works; JAR findings silently missing |
| Java DB in `<cache-dir>/java-db` | tomcat 9.0.50: 547 findings vs 500 without (47 in JARs: 8 CRITICAL, 20 HIGH, 14 MEDIUM, 5 LOW) |

Cost of the Java DB per Job: 948 MiB compressed download (13 s from a local
mirror, much longer over a WAN), 1.5 GiB unpacked, about 2.5 GiB of ephemeral
disk with the tarball. Scan time unchanged; client peak 531 MiB vs 395 MiB on
tomcat.

### Version and `/version`

    GET /version   (no token)
    {"Version":"0.76.1","VulnerabilityDB":{"Version":2,"NextUpdate":"...",
     "UpdatedAt":"2026-11-03T19:16:30Z","DownloadedAt":"..."}}
    GET /healthz -> 200 ok
    POST /twirp/... with a bad token -> 401 unauthenticated

Clients 0.75.0 and 0.60.0 against a 0.76.1 server: exit 0, same findings, no
warning. Nothing enforces a version match.

### Multi-arch layouts

| Layout and `--input` | Result |
|---|---|
| nested index (`crane pull --format oci`), no digest | first child (amd64) only |
| same, `--platform linux/arm64` | `--platform` ignored, amd64 |
| same, `@<child digest>` | FATAL, not in `index.json` |
| one top-level `index.json` entry per child, `@sha256:<child>` | that child scanned |
| same, `@sha256:<attestation child>` | FATAL `archive/tar: invalid tar header` |

Blobs are copied as they are, so digests round-trip unchanged.

### Report size

| Image | Findings | Full JSON | `--list-all-pkgs=false` | Minimal template |
|---|---|---|---|---|
| alpine 3.19 | 10 | 46 KB | 25 KB | 1.2 KB |
| nginx 1.25 | 836 | 3.7 MB | 3.2 MB | - |
| tomcat 9.0.50 | 500 | 3.2 MB | 2.4 MB | - |
| python 3.9 | 13,642 | 59.2 MB | 57.3 MB | 1.67 MB |

`--format template` output is valid JSON with one entry per finding (template
in the design). A template sees only the results, not `Trivy.Server`.

### Scan time and memory

Cold server cache per row, DB loaded. Client peak is the cgroup peak and
includes page cache.

| Image | Layout | Findings (no Java DB / Java DB) | Wall | Client peak | Server RSS |
|---|---|---|---|---|---|
| alpine 3.19 | 22 MiB | 10 / 10 | 0.5 s | 37 MiB | 110 MB |
| nginx 1.25 (all platforms) | 541 MiB | 836 / 836 | 1.1 s | 148 MiB | 151 MB |
| eclipse-temurin 17 jre | 107 MiB | 57 / 57 | 1.0 s | 153 MiB | 121 MB |
| tomcat 9.0.50 | 342 MiB | 500 / 547 | 2.1 s | 395 / 531 MiB | 141 MB |
| python 3.9 | 419 MiB | 13,642 / 13,642 | 4.7 s | 927 / 941 MiB | 373 MB |

Warm server cache: alpine 0.5 s, tomcat 0.6 s. Concurrency not measured.

### Corrections to the design

- The design's client flags crash on any image with a JAR. Disabled mode needs
  `--skip-files`.
- Full JSON can exceed the 32 MiB report cap. Use the minimal template.
- `--platform` does not select a child of a layout; write one top-level
  descriptor per child and scan by digest.
- No in-process TLS on the server.
- A version mismatch is not detected by Trivy.
