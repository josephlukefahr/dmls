# Scripts (bash / WSL / macOS / Linux)

This folder contains convenience scripts used to build and exercise the dmls example scenario. The scripts are intentionally simple shell wrappers around the Rust CLI (the binary produced by `cargo build`) and are intended for manual testing, demos, and reproducible examples.

This README documents:

- prerequisites and environment
- an overview of how the example scenario works
- a per-script description and expected inputs/outputs
- recommended workflows and troubleshooting tips

## Quick overview: what these scripts do

The scripts automate a short, end-to-end MLS (Messaging Layer Security) example implemented by this repository. The overall scenario is:

1. Build the `dmls` CLI binary from the Rust source.
2. Generate per-participant persistent "state" files (JSON) representing long-term identity and key material.
3. Generate key-package blobs (key packages) used for group onboarding.
4. Create send-groups / welcome messages to add members to groups.
5. Demonstrate sending, processing, and inspecting encrypted application messages and commits.

The scripts are named to reflect those steps and can be run individually or chained together.

## Prerequisites

- Rust toolchain with `cargo` in PATH. Tested with recent stable Rust.
- A POSIX shell for the `.bash` scripts (WSL on Windows is recommended) or PowerShell if you prefer the Windows scripts (not all PowerShell scripts are included in this folder).
- The repository built successfully at least once (the scripts call `cargo build` or expect the binary at `target/debug/dmls`).

Note: The scripts in this directory are Bash scripts (with filenames like `*.bash`). If you are on native Windows PowerShell see the project root for PowerShell equivalents (or run the Bash scripts from WSL).

## How the example program works (high-level contract)

- Inputs: plain files or simple CLI arguments. Participant identities are stored as JSON state files (e.g. `alice_state.json`). Key packages are output as base64 blobs (e.g. `alice_kp.b64`). Group operations consume those artifacts and emit welcome blobs.
- Outputs: state files, key package files, welcome blobs, encrypted message files and logs written to the `scripts/` directory.
- Success criteria: scripts finish without errors and produce the expected files. The example culminates with at least one application message being produced and processed by all participants and optionally a commit/merge applied.
- Failure modes: missing `cargo`, build failures, or missing/incorrect file permissions. The scripts do minimal validation and will fail loudly in these cases.

Edge cases to consider

- Re-running a script may overwrite files. Some scripts accept a `force` flag or check for existence; inspect the script header for details.
- Large numbers of key packages or participants are not optimized—these scripts are for examples and tests, not performance evaluation.

## Files / scripts in this directory

The important files are listed below with detailed descriptions and example usages. All paths below are relative to this `scripts/` directory.

- `0-build.bash`
    - Purpose: Build the Rust `dmls` binary using `cargo build` for the current toolchain/profile.
    - Typical usage: `./0-build.bash`
    - Effects: Produces `target/debug/dmls` (or `target/debug/dmls.exe` on Windows via WSL). If you want an optimized build use `cargo build --release` manually.

- `1-gen_states.bash`
    - Purpose: Create per-participant persistent state files. These represent identity material and any long-lived keys needed by the example.
    - Typical usage: `./1-gen_states.bash`
    - Outputs: `alice_state.json`, `bob_state.json`, `charlie_state.json` in the `scripts/` directory (or wherever the script is configured to write).
    - Notes: The script calls the `dmls` CLI to generate and export state. The JSON files are reused by subsequent steps.

- `2-gen_kps.bash`
    - Purpose: Generate KeyPackage blobs (base64) for each participant. Key packages are required to create or join groups in MLS.
    - Typical usage: `./2-gen_kps.bash [per-participant] [force]
        - `per-participant` (optional): Number of key packages to generate per participant. Defaults to `1`.
        - `force` (optional): When present and non-empty the script will overwrite existing key package files.
    - Outputs: files like `alice_kp.b64`, `bob_kp.b64`, `charlie_kp.b64`.
    - Example: `./2-gen_kps.bash` -> generate 2 key packages per participant and overwrite existing files.

- `3-gen_send_groups.bash`
    - Purpose: Create send-group artifacts and welcome messages used to add members to a group. This wraps CLI commands that create a group and export the resulting welcome blob.
    - Typical usage: `./3-gen_send_groups.bash`
    - Outputs: `welcome.b64` or similarly named artifacts which can be consumed by the apply/inspect scripts.

- `5a-encrypt.bash`
    - Purpose: Produce an encrypted application message from a sender to the group.
    - Typical usage: `./5a-encrypt.bash`
    - Outputs: an encrypted message file (naming depends on script internals) which will be processed by the next steps.

- `5b-process.bash`
    - Purpose: Have each participant process incoming messages. This demonstrates decryption and state update logic.
    - Typical usage: `./5b-process.bash`

- `5c-update.bash`
    - Purpose: Generate a commit/handshake update for the group (e.g., change proposals, rekeying) and apply it. This shows how commits are created and applied.
    - Typical usage: `./5c-update.bash`

- `5d-commit.bash`
    - Purpose: Finalize and commit updates to group state across participants. Depending on the example this may be combined with `5c`.
    - Typical usage: `./5d-commit.bash`

- `5e-inspect.bash`
    - Purpose: Inspect artifacts (welcome blobs, messages, state files) to help debugging and understanding the MLS structures.
    - Typical usage: `./5e-inspect.bash`

- `lipsum`
    - Purpose: An included sample file used to generate filler application messages. Not required for the core scenario.

## Example workflows

Run the full example (recommended from a POSIX shell in the `scripts/` directory):

1. Build the binary:
```bash
     ./0-build.bash
```
2. Generate participant states:
```bash
     ./1-gen_states.bash
```
3. Generate key packages (one per participant):
```bash
     ./2-gen_kps.bash
```
4. Create group and send welcome(s):
```bash
     ./3-gen_send_groups.bash
```
5. Send an application message and process it:
```bash
     ./5a-encrypt.bash
     ./5b-process.bash
```
6. Optionally run update/commit/inspect steps:
```bash
     ./5c-update.bash
     ./5e-inspect.bash
```

## Troubleshooting

- If a script fails due to `cargo` not found, ensure the Rust toolchain is installed and `cargo` is on PATH in your shell.
- If the binary is missing, run `cargo build` manually in the repository root and re-run `0-build.bash`.
- Inspect intermediate files (state JSON, .b64 blobs) to ensure inputs are present. Scripts perform minimal validation by design.

Contributing and extending the scripts

- The scripts are intentionally small and readable. If you add new example flows, prefer creating new scripts with clear names (e.g., `4-remove_member.bash`).
- When adding more complex checks, consider writing small integration tests in Rust or adding a `tests/` harness.

## License and attribution

These scripts are part of the overall dmls project and follow the repository license. See the top-level `LICENSE` file for details.

If anything in this README is unclear or you'd like walkthrough examples added, tell me which parts you'd like expanded and I will update this file.
