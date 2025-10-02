#![doc = include_str!("../README.md")]
#![allow(clippy::multiple_crate_versions)]

mod helpers;
mod openmls_keys;
mod openmls_kvstore;
mod provider;
mod state;

use crate::{
    helpers::{
        apply_commit, force_add_members_base64, gen_kp_base64, gen_send_group, plaintext,
        process_proto_msg, process_welcome, send_group, send_group_inject_psks_base64,
        send_group_update_base64, stdin_base64_extract, stdin_base64_to_kp,
        stdin_base64_to_mls_msg_in, stdin_create_message_base64,
    },
    openmls_keys::SignatureKeyPair,
    provider::DmlsProvider,
    state::DmlsState,
};
use clap::{Parser, Subcommand};
use openmls::framing::{MlsMessageBodyIn, ProcessedMessageContent, ProtocolMessage};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::{
    fs::{read_to_string as read_file_to_string, write as write_string_to_file},
    io::{BufRead, stdin},
};

/// Command-line arguments for the DMLS example agent.
///
/// The CLI exposes two high-level flows:
/// - `gen-state` to create a new per-participant state JSON file
/// - `use-state` to load an existing state and run subcommands that interact with group state
///
/// Example:
///
/// ```text
/// # create a new state
/// cargo run -- gen-state ./alice_state.json --signature-scheme Ed25519
/// # use a saved state to generate a key package
/// cargo run -- use-state ./alice_state.json gen-kp
/// ```
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Command to use for loading state
    #[command(subcommand)]
    state_command: StateCommands,
}

/// Top-level state commands supported by the CLI.
///
/// - `GenState` creates a new JSON state file containing the generated signature key pair.
/// - `UseState` loads an existing state file and runs `MainCommands` against it.
/// - `InspectMessages` attempts to deserialize base64-encoded MLS messages from stdin and
///   pretty-prints them for debugging.
#[derive(Clone, Debug, Subcommand)]
enum StateCommands {
    /// Create a new per-participant state and write it to `state_path`.
    GenState {
        /// Path to a JSON file to write (required)
        state_path: String,
        /// Digital signature algorithm to use to generate signing key (optional)
        #[arg(long, default_value = "Ed25519")]
        signature_scheme: String,
    },
    /// Load an existing state and run a main command using that state.
    UseState {
        /// Path to a JSON file to update (required)
        state_path: String,
        /// Ciphersuite to use (optional)
        #[arg(long, default_value = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")]
        ciphersuite: String,
        /// Exporter length to use for DMLS exporter PSK (optional)
        #[arg(long, default_value_t = 32)]
        exporter_length: usize,
        /// Main command to run using the loaded state
        #[command(subcommand)]
        main_command: MainCommands,
    },
    /// Inspect base64-encoded MLS messages read from stdin and pretty-print them.
    InspectMessages {},
}

/// Main commands that operate on a loaded `DmlsState`.
///
/// - `GenKp` exports a KeyPackage for this participant.
/// - `GenSendGroup` creates a send-group (group creator flow) and accepts key packages on stdin.
/// - `Update`, `Commit` and `Encrypt` map to send-group update, commit-inject, and message creation flows.
#[derive(Clone, Debug, Subcommand)]
enum MainCommands {
    /// Generate a KeyPackage (prints base64 to stdout).
    GenKp {},
    /// Process incoming messages (reads base64 messages from stdin).
    Process {},
    /// Encrypt plaintext lines into base64 application messages (reads plaintext from stdin).
    Encrypt {},
    /// Create a self-update commit (prints base64 commit to stdout).
    Update {},
    /// Inject queued PSKs into send-group and return commit (base64).
    Commit {},
    /// Create a send-group (creator) and add members via key packages (stdin).
    GenSendGroup {},
}

/// High-level processing of a ProtocolMessage.
///
/// This helper loads the group referenced by the protocol message, processes the message,
/// and handles application messages and staged commits. Application message plaintexts are
/// printed to stdout; staged commits are applied to the group and may queue exporter PSKs.
///
/// Example:
///
/// ```ignore
/// process_proto_msg_main(&mut provider, proto_msg, ciphersuite, exporter_length);
/// ```
fn process_proto_msg_main(
    provider: &mut DmlsProvider,
    proto_msg: ProtocolMessage,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) {
    match process_proto_msg(provider, proto_msg) {
        Err(e) => {
            log::error!("Error processing message: {e}");
        }
        Ok((mut g, m)) => {
            log::warn!("Processed message:\n{m:#?}");
            match m.into_content() {
                ProcessedMessageContent::ApplicationMessage(app_msg) => match plaintext(app_msg) {
                    Err(e) => {
                        log::error!("Error getting plaintext: {e}");
                    }
                    Ok(pt) => {
                        println!("{pt}");
                    }
                },
                ProcessedMessageContent::StagedCommitMessage(commit) => {
                    if let Err(e) =
                        apply_commit(provider, &mut g, *commit, ciphersuite, exporter_length)
                    {
                        log::error!("Error applying commit: {e}");
                    }
                }
                _ => {
                    log::error!("Unsupported processed message content");
                }
            }
        }
    }
}

/// Entry point for the DMLS CLI example binary.
///
/// The `main` function initializes logging, parses command-line arguments, and dispatches
/// to the appropriate flow: creating a new `DmlsState`, or loading an existing state and
/// running a subcommand (generate key package, create send-group, process messages, etc.).
///
/// Behaviour summary:
/// - `gen-state`: creates a JSON state file with a newly-generated signing key pair.
/// - `use-state`: loads the JSON state, creates a `DmlsProvider` and executes `MainCommands`.
/// - All operations that produce or consume protocol artifacts use base64 blobs on stdin/stdout
///   to make them easy to pipe into the example scripts.
///
/// Example:
///
/// ```text
/// cargo run -- gen-state ./alice_state.json --signature-scheme Ed25519
/// cargo run -- use-state ./alice_state.json gen-kp
/// ```
fn main() {
    // logging
    pretty_env_logger::init();
    // command-line args
    let args = CliArgs::parse();
    log::info!("Command-line arguments: {args:?}");
    // crypto
    let crypto = RustCrypto::default();
    // process state command
    match &args.state_command {
        StateCommands::InspectMessages {} => {
            log::debug!("Trying to inspect message(s) from stdin");
            // read lines from stdin; for each: try to deserialize and then pretty-print
            for line in stdin().lock().lines() {
                match stdin_base64_to_mls_msg_in(line) {
                    Err(e) => {
                        log::error!("Error inspecting message: {e}");
                    }
                    Ok(m) => {
                        log::warn!("Message:\n{:#?}", m);
                    }
                }
            }
        }
        StateCommands::GenState {
            state_path,
            signature_scheme,
        } => {
            log::debug!("Creating new state");
            // signature scheme
            let signature_scheme = match signature_scheme.as_str() {
                "Ed25519" => SignatureScheme::ED25519,
                _ => {
                    log::warn!("Invalid signature algorithm; using EdDSA with Curve25519");
                    SignatureScheme::ED25519
                }
            };
            // new state object
            let state =
                DmlsState::new(SignatureKeyPair::from_crypto(&crypto, signature_scheme).unwrap());
            // save new state
            log::info!("Path to write state: {state_path}");
            log::info!("Updated state to write:\n{state:#?}");
            write_string_to_file(state_path, json_encode(&state).unwrap()).unwrap();
        }
        StateCommands::UseState {
            state_path,
            ciphersuite,
            exporter_length,
            main_command,
        } => {
            log::debug!("Trying to use existing state");
            // ciphersuite
            let ciphersuite = match ciphersuite.as_str() {
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" => {
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                }
                "MLS_128_DHKEMP256_AES128GCM_SHA256_P256" => {
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                }
                _ => {
                    log::warn!(
                        "Invalid ciphersuite; using MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
                    );
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                }
            };
            // provider
            let mut provider = DmlsProvider::new(
                json_decode(&read_file_to_string(state_path).unwrap()).unwrap(),
                crypto,
            );
            log::info!("Provider based on existing state:\n{provider:#?}");
            // process main command
            match main_command {
                MainCommands::GenKp {} => {
                    log::debug!("Trying to generate new key package");
                    match gen_kp_base64(&provider, ciphersuite) {
                        Err(e) => {
                            log::error!("Error generating key package: {e}");
                        }
                        Ok(kp) => {
                            println!("{kp}");
                        }
                    }
                }
                MainCommands::GenSendGroup {} => {
                    log::debug!("Trying to generate new send group");
                    match gen_send_group(&mut provider, ciphersuite) {
                        Err(e) => {
                            log::error!("Error generating send group: {e}");
                        }
                        Ok(mut sg) => {
                            log::debug!("Trying to validate key packages provided via stdin");
                            let mut kps = Vec::new();
                            for line in stdin().lock().lines() {
                                match stdin_base64_to_kp(&provider, line) {
                                    Err(e) => {
                                        log::error!("Error validating key package: {e}");
                                    }
                                    Ok(kp) => {
                                        log::info!("Validated key package:\n{kp:#?}");
                                        kps.push(kp);
                                    }
                                }
                            }
                            log::debug!("Adding validated key packages to send group");
                            match force_add_members_base64(&provider, &mut sg, &kps) {
                                Err(e) => {
                                    log::error!("Error adding members to send group: {e}");
                                }
                                Ok(welcome) => {
                                    log::warn!("Send group:\n{sg:#?}");
                                    println!("{welcome}");
                                }
                            }
                        }
                    }
                }
                MainCommands::Update {} => {
                    log::debug!("Trying to update in send group");
                    match send_group_update_base64(&mut provider, ciphersuite, *exporter_length) {
                        Err(e) => {
                            log::error!("Error updating in send group: {e}");
                        }
                        Ok(commit) => {
                            println!("{commit}");
                        }
                    }
                }
                MainCommands::Process {} => {
                    log::debug!("Trying to process incoming messages");
                    for line in stdin().lock().lines() {
                        match stdin_base64_extract(line) {
                            Err(e) => {
                                log::error!("Error extracting message: {e}");
                            }
                            Ok(MlsMessageBodyIn::Welcome(welcome)) => {
                                match process_welcome(&provider, welcome) {
                                    Err(e) => {
                                        log::error!("Error processing welcome: {e}");
                                    }
                                    Ok(g) => {
                                        log::warn!("Group joined:\n{g:#?}");
                                    }
                                }
                            }
                            Ok(MlsMessageBodyIn::PublicMessage(pub_msg_in)) => {
                                process_proto_msg_main(
                                    &mut provider,
                                    pub_msg_in.into(),
                                    ciphersuite,
                                    *exporter_length,
                                );
                            }
                            Ok(MlsMessageBodyIn::PrivateMessage(prv_msg_in)) => {
                                process_proto_msg_main(
                                    &mut provider,
                                    prv_msg_in.into(),
                                    ciphersuite,
                                    *exporter_length,
                                );
                            }
                            Ok(_) => {
                                log::error!("Unsupported wire format");
                            }
                        }
                    }
                }
                MainCommands::Commit {} => {
                    log::debug!("Trying to inject queued PSKs into send group");
                    match send_group_inject_psks_base64(&mut provider, ciphersuite) {
                        Err(e) => {
                            log::error!("Error injecting PSKs into send group: {e}");
                        }
                        Ok(commit) => {
                            println!("{commit}");
                        }
                    }
                }
                MainCommands::Encrypt {} => {
                    log::debug!("Trying to encrypt messages in send-group");
                    match send_group(&provider) {
                        Err(e) => {
                            log::error!("Error getting send group: {e}");
                        }
                        Ok(mut sg) => {
                            // assumes line is a utf-8 string
                            for line in stdin().lock().lines() {
                                match stdin_create_message_base64(&provider, &mut sg, line) {
                                    Err(e) => {
                                        log::error!("Error creating message: {e}");
                                    }
                                    Ok(msg) => {
                                        println!("{msg}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // recover updated state from agent & save
            let state: DmlsState = provider.into();
            log::info!("Path to write state: {state_path}");
            log::info!("Updated state to write:\n{state:#?}");
            write_string_to_file(state_path, json_encode(&state).unwrap()).unwrap();
        }
    }
    // done!
}
