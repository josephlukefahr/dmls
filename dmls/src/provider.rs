//! DMLS provider implementation wiring OpenMLS crypto and storage to application state.
//!
//! `DmlsProvider` is the glue between the `DmlsState` (persistent application state), the
//! `OpenMlsKeyValueStore` (storage backend), and the cryptographic provider (`RustCrypto`).
//! It implements the `OpenMlsProvider` trait required by the OpenMLS library and the `Signer`
//! trait used when producing credentials or signing commits.
//!
//! Example (pseudo-Rust):
//!
//! ```ignore
//! let provider = DmlsProvider::new(state, RustCrypto::default());
//! let storage = provider.storage();
//! let signature = provider.sign(payload)?;
//! ```

use super::{openmls_kvstore::OpenMlsKeyValueStore, state::DmlsState};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    OpenMlsProvider,
    crypto::OpenMlsCrypto,
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};

/// The main provider struct for DMLS, implementing the OpenMLS provider interface.
///
/// Example usage of `DmlsProvider`:
///
/// ```ignore
/// let state = DmlsState::new(signature_key_pair);
/// let provider = DmlsProvider::new(state, RustCrypto::default());
/// let storage = provider.storage();
/// ```
#[derive(Debug)]
pub struct DmlsProvider {
    /// The persistent DMLS state, including protocol version and key-value store.
    state: DmlsState,
    /// The cryptographic backend (RustCrypto) for OpenMLS operations.
    crypto: RustCrypto,
}

#[allow(clippy::from_over_into)]
impl Into<DmlsState> for DmlsProvider {
    fn into(self) -> DmlsState {
        self.state
    }
}

impl DmlsProvider {
    /// Creates a new `DmlsProvider` with the given state and cryptographic backend.
    ///
    /// # Arguments
    /// * `state` - The persistent DMLS state.
    /// * `crypto` - The cryptographic backend (RustCrypto).
    ///
    /// # Returns
    /// A new `DmlsProvider` instance.
    pub fn new(state: DmlsState, crypto: RustCrypto) -> Self {
        Self { state, crypto }
    }
    /// Returns a reference to the internal DMLS state.
    pub fn state(&self) -> &DmlsState {
        &self.state
    }
    /// Returns a mutable reference to the internal DMLS state.
    pub fn state_mut(&mut self) -> &mut DmlsState {
        &mut self.state
    }
}

/// Implements the OpenMLS provider trait for DMLS, wiring up crypto, random, and storage providers.
impl OpenMlsProvider for DmlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = OpenMlsKeyValueStore;
    /// Returns a reference to the OpenMLS storage provider (key-value store).
    fn storage(&self) -> &Self::StorageProvider {
        self.state.openmls_values()
    }
    /// Returns a reference to the cryptographic backend (RustCrypto).
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    /// Returns a reference to the random provider (RustCrypto).
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Signer for DmlsProvider {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(
                self.state.signature_key_pair().signature_scheme(),
                payload,
                self.state.signature_key_pair().private_key_raw(),
            )
            .map_err(SignerError::CryptoError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        self.state.signature_key_pair().signature_scheme()
    }
}
