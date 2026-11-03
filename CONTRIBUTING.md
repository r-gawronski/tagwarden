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
make manifests generate fmt vet lint test
go tool govulncheck ./...
```

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
through the proxy.

## Security

Never report vulnerabilities in public issues or pull requests. See [SECURITY.md](SECURITY.md).

If your change touches a trust boundary (network, credentials, signatures), update [docs/threat-model.md](docs/threat-model.md) in the same pull request.
