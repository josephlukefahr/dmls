#![doc = include_str!("../README.md")]
#![allow(clippy::multiple_crate_versions)]

mod agent;
mod openmls_keys;
mod openmls_kvstore;
mod provider;
mod state;

use crate::{
    agent::DmlsAgent, openmls_keys::SignatureKeyPair, provider::DmlsProvider, state::DmlsState,
};
use clap::{Parser, Subcommand};
use openmls::framing::MlsMessageIn;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::SignatureScheme;
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::{
    fs::{read_to_string as read_file_to_string, write as write_string_to_file},
    io::{Read, Write, stdin, stdout},
};
use tls_codec::{Deserialize, Serialize};

/// Simple DMLS agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Command to use for loading state
    #[command(subcommand)]
    state_command: StateCommands,
}

#[derive(Clone, Debug, Subcommand)]
enum StateCommands {
    GenState {
        /// Path to a JSON file to write (required)
        state_path: String,
        /// Digital signature algorithm to use to generate signing key (optional)
        #[arg(long, default_value = "Ed25519")]
        signature_scheme: String,
    },
    UseState {
        /// Path to a JSON file to update (required)
        state_path: String,
        #[command(subcommand)]
        main_command: MainCommands,
    },
    InspectMessage {},
}

#[derive(Clone, Debug, Subcommand)]
enum MainCommands {
    GenKp {},
}

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
        StateCommands::InspectMessage {} => {
            log::debug!("Trying to inspect message from stdin");
            let mut buffer = Vec::new();
            stdin().read_to_end(&mut buffer).unwrap();
            match MlsMessageIn::tls_deserialize_exact(&buffer) {
                Err(e) => {
                    println!("Error inspecting message: {e}");
                }
                Ok(m) => {
                    println!("{:#?}", m);
                }
            }
        }
        StateCommands::GenState {
            state_path,
            signature_scheme,
        } => {
            log::debug!("Creating new state");
            // new state object
            let state = DmlsState::new(
                SignatureKeyPair::from_crypto(
                    &crypto,
                    match signature_scheme.as_str() {
                        "Ed25519" => SignatureScheme::ED25519,
                        _ => {
                            log::warn!("Invalid signature algorithm; using EdDSA with Curve25519");
                            SignatureScheme::ED25519
                        }
                    },
                )
                .unwrap(),
            );
            // save new state
            log::info!("Path to write state: {state_path}");
            log::info!("Updated state to write: {state:?}");
            write_string_to_file(state_path, json_encode(&state).unwrap()).unwrap();
        }
        StateCommands::UseState {
            state_path,
            main_command,
        } => {
            log::debug!("Trying to use existing state");
            // agent
            let mut agent = DmlsAgent::new(DmlsProvider::new(
                json_decode(&read_file_to_string(state_path).unwrap()).unwrap(),
                crypto,
            ));
            log::info!("Agent based on existing state: {agent:?}");
            // process main command
            match main_command {
                MainCommands::GenKp {} => {
                    log::debug!("Trying to generate new key package");
                    stdout()
                        .write_all(&agent.gen_kp().unwrap())
                        .unwrap();
                }
            }
            // recover updated state from agent & save
            let provider: DmlsProvider = agent.into();
            let state: DmlsState = provider.into();
            log::info!("Path to write state: {state_path}");
            log::info!("Updated state to write: {state:?}");
            write_string_to_file(state_path, json_encode(&state).unwrap()).unwrap();
        }
    }
    // done!
}
