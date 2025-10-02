# DMLS Workspace

This workspace contains multiple Rust crates related to the Distributed MLS (DMLS) example and
the OpenMLS library used for experimentation and examples.

Crates included:

- `dmls` — Example command-line agent and utilities for working with MLS groups. This crate
  contains the CLI, helper scripts, and small storage/provider implementations used in the examples.
- `openmls` — The OpenMLS library and related crates (subfolders) used as dependencies by `dmls`.

Deprecation note:

The crate named `distributed_mls` has been deprecated and replaced by `dmls`. Please use `dmls`
going forward.

Quick start (from the `dmls` crate directory):

```text
cd dmls
cargo run -- --help
```

For more details about the `dmls` crate (CLI usage and example scripts), see `dmls/README.md`.
