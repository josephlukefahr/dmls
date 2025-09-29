//! The main persistent state struct for a DMLS agent.
//!
//! # DmlsState
//!
//! This module defines the `DmlsState` struct, which encapsulates the persistent state for a DMLS (Distributed Messaging Layer Security) client or server.
//!
//! The state includes the OpenMLS protocol version in use and an in-memory, thread-safe key-value store for all OpenMLS-related values. The key-value store is implemented using `OpenMlsKeyValueStore`, which encodes all keys and values as base64 for safe storage of binary data.
//!
//! ## Features
//! - Tracks the MLS protocol version for the current state
//! - Stores all OpenMLS cryptographic and group state in a single, serializable struct
//! - Provides a default implementation for easy initialization
//! - Designed for use in persistent storage, testing, or as a backend for DMLS applications

use super::{openmls_keys::SignatureKeyPair, openmls_kvstore::OpenMlsKeyValueStore};
use serde::{Deserialize, Serialize};

/// The main persistent state struct for a DMLS agent.
///
/// Holds the current OpenMLS protocol version and a key-value store for all OpenMLS-related values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmlsState {
    signature_key_pair: SignatureKeyPair,
    /// The in-memory, thread-safe key-value store for all OpenMLS values.
    openmls_values: OpenMlsKeyValueStore,
}

impl DmlsState {
    /// Creates a new `DmlsState` with the specified MLS protocol version.
    ///
    /// # Returns
    /// A new `DmlsState` instance with an empty key-value store.
    pub fn new(signature_key_pair: SignatureKeyPair) -> Self {
        // done
        Self {
            signature_key_pair,
            openmls_values: Default::default(),
        }
    }
    pub fn signature_key_pair(&self) -> &SignatureKeyPair {
        &self.signature_key_pair
    }
    /// Returns a reference to the internal OpenMLS key-value store.
    pub fn openmls_values(&self) -> &OpenMlsKeyValueStore {
        &self.openmls_values
    }
}
