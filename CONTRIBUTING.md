# Contributing

Contributions are welcome under the [Apache-2.0](LICENSE) license.

Start with the [README](README.md) for what wscanner is, [specs/cli-contract.md](specs/cli-contract.md) for the surface every change must keep, and [specs/](specs/README.md) for what is planned. We write issues, PRDs and pull requests by the rules in [waffuruai/ops `.agents`](https://github.com/waffuruai/ops/tree/dev/.agents): open an issue first, keep a PR to one change, and say in its description which spec it updated or "no PRD impact".

Before opening a pull request, run:

```bash
python3 -m unittest discover -s python -p 'test_*.py'
python/test-ca-trust.sh
bash -n python/bin/wscanner python/*.sh && shellcheck -x python/bin/wscanner python/*.sh
```

A change to the CLI, the JSON output, the exit codes or the cache schema updates [specs/cli-contract.md](specs/cli-contract.md) in the same PR and follows its change rule: additive only, or bump `schema`. A new check needs a test that runs offline. Python stays standard-library only and runs on 3.9.

Keep examples and fixtures generic. Do not commit secrets, tokens, real email addresses, usernames, machine identifiers, personal paths or captured scan output. A finding from your own machine is reported as a minimal reproducer, never as a pasted report.

Security reports do not go in a pull request or a public issue. Follow [SECURITY.md](SECURITY.md).
