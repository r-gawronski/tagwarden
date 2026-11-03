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

## Security

Never report vulnerabilities in public issues or pull requests. See [SECURITY.md](SECURITY.md).

If your change touches a trust boundary (network, credentials, signatures), update [docs/threat-model.md](docs/threat-model.md) in the same pull request.
