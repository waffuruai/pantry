# Specs

PRDs and design docs for wpantry: a PRD states the problem, the functional, security and performance criteria, and the phases; a design doc says how. How wpantry works today is [docs/architecture.md](../docs/architecture.md).

| Spec | What | Status |
|---|---|---|
| [cli-contract.md](cli-contract.md) | The CLI, exit codes, JSON and cache every implementation keeps | frozen (schema 1) |

## Archived

Kept as the record of what was decided and why; no longer updated.

| Spec | What | Archived |
|---|---|---|
| [archived/01-rust-port.md](archived/01-rust-port.md) | Port wpantry to Rust as a crate and a signed static binary | 2026-10-31: shipped as v0.1.0 and v0.2.0; what it left open is in [docs/architecture.md](../docs/architecture.md#what-the-port-left-open-and-where-it-closed) |
| [archived/rust-port-design.md](archived/rust-port-design.md) | The port's detail: readers, ecosystem strings, comparators, dependencies | 2026-10-31: carried into [docs/architecture.md](../docs/architecture.md) |
