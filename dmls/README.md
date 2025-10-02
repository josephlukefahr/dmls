Distributed Messaging Layer Security (DMLS) command-line agent.

# Distributed Messaging Layer Security (DMLS) command-line agent

This crate provides a small, example DMLS agent implemented in Rust that demonstrates how to
use OpenMLS primitives to create groups, add members, send encrypted application messages,
process incoming messages, and manage short-lived PSKs (exporter PSKs) produced during commits.

The intent of this crate is educational and experimental: the binary and helper scripts in the
`scripts/` directory can be used to run a short end-to-end scenario (build, generate per-participant
state, create key packages, form a group, send messages, process welcomes/commits).

## Quick start (from the crate root):

1. Build the crate:
```
	cargo build
```
2. Create a new state (example with Ed25519 signatures):
```
	cargo run -- gen-state ./alice_state.json --signature-scheme Ed25519
```
3. Generate a key package (after creating state):
```
	cargo run -- use-state ./alice_state.json gen-kp
```
4. Use the `scripts/` helpers for a full scenario (recommended): see `scripts/README.md` for details.

## Features and focus

- Minimal, readable example of integrating OpenMLS into an application-level agent.
- Uses an in-memory, serializable key-value store that implements the OpenMLS `StorageProvider` trait.
- Provides a small CLI for generating per-participant state, exporting key packages, creating a send-group
  welcome, producing commits, encrypting messages, and processing incoming artifacts.

## When to use this crate

- Learning how MLS groups, key packages, welcomes, commits, and application messages interact.
- As a reference for wiring OpenMLS provider/crypto/storage traits into an application.

See the `scripts/` directory for step-by-step example scripts and the source `src/` files for
inline documentation and usage examples.
