# Contributing

Thanks for helping. Keep changes small and focused: one logical change per pull request.

## Developer Certificate of Origin

Every commit must be signed off. Use `git commit -s`. This adds a line like:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The sign-off states that you wrote the change or have the right to submit it under the project license. See the full text at https://developercertificate.org/. A CI check fails any pull request that contains a commit whose sign-off does not match the commit author email.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope): ...`, `fix: ...`, `test: ...`, `docs: ...`, `ci: ...`, `chore: ...`.

## Tests first

Write a failing test before the code that makes it pass. Use table tests for pure logic, envtest for controllers, in-process registries for sync code and kind for end-to-end tests.

## Before opening a pull request

Run:

```sh
make lint test chart-check vulncheck
```

If you changed API types or markers, also run `make manifests generate fmt vet`.

If you changed Go dependencies, also run `make notice`. CI fails when `NOTICE` is out of date.

Commit any generated files that change. CI runs the same checks.

## End-to-end tests

`make test-e2e` needs Docker, kubectl and Helm. It creates a kind cluster
(kindnet enforces NetworkPolicy), builds the operator image, loads it into
kind, installs the chart from `dist/chart` and deletes the cluster when the
tests pass.

The mirror tests deploy into `e2e-infra` a source and a target registry
(zot, TLS from a CA the test generates, basic auth on the target) and a
Squid proxy with basic auth. The source is reachable as
`source.example.internal` only through the proxy. NetworkPolicies let the
sync pods reach DNS, the proxy and the target, nothing else. The tests seed
the source, start sync Jobs with `kubectl create job --from=cronjob/...`
and check the target, the referrers and the mirror status. CI needs no
internet access beyond pulling images.

`E2E_INTERNET=1 make test-e2e` also mirrors `registry.k8s.io/pause`
through the proxy. `E2E_SKIP_IMAGE_BUILD=1` skips `make docker-build` and
loads an image you built as `example.com/tagwarden:v0.0.1`. CI uses it to
build the image with a layer cache first. That cache only helps when the Go
sources are unchanged: BuildKit cache mounts are not exported, so a code
change recompiles the manager (about 3 minutes).

## CI

Changes that touch only Markdown, `docs/`, `LICENSE` or
`.github/CODEOWNERS` skip CI, CodeQL and e2e. DCO still runs.

On pull requests the e2e workflow runs only when the pull request has the
`e2e` label: when the label is added and on every push after that. Without
the label the job is skipped, and a skipped check shows as success in the
pull request. It always runs on pushes to `main` and weekly.

The vulnerability gate tests download the scanner database (about 1.6 GiB)
and pull images from the internet, so they run separately: `make
test-e2e-gate`. In CI they run on pull requests with the `e2e-gate` label,
nightly and on manual dispatch. Add the label when a change touches
`internal/vuln/` or the gate code.

Add the `e2e` label before merge when a change touches the controller, the
sync code, the registry transport, the chart or the e2e tests. Leave it off
while you iterate on review fixes if you like, but add it before the last
push.

## Merge checklist

Maintainers merge with squash. The pull request title becomes the commit
message, so write it as a Conventional Commit.

- CI, CodeQL and DCO are green.
- A pull request that touches the controller, sync, registry, chart or e2e
  code has a green e2e run on its last commit. A skipped e2e check does not
  count. A ruleset on main requires a pull request, squash merge, linear
  history and green lint, test, generate-check, govulncheck, chart,
  analyze, dco and gitleaks checks. The e2e runs are opt-in by label, so
  the reviewer enforces this item.

## Security

Never report vulnerabilities in public issues or pull requests. See [SECURITY.md](SECURITY.md).

If your change touches a trust boundary (network, credentials, signatures), update [docs/threat-model.md](docs/threat-model.md) in the same pull request.
