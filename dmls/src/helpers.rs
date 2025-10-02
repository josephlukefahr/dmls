//! Helper functions for DMLS CLI.
//!
//! Helper wrappers that bridge the `DmlsProvider` and OpenMLS operations to simple, testable
//! functions that produce or consume base64-encoded blobs. These wrappers are used by the CLI
//! and the example `scripts/` to perform high-level operations without duplicating OpenMLS glue code.
//!
//! The functions in this module are intentionally small and return `Result<..., Box<dyn Error>>`
//! to simplify piping and scripting. Common operations include:
//! - Generating key packages (base64)
//! - Creating a send group and producing a welcome (base64)
//! - Creating application messages (base64)
//! - Processing welcomes and protocol messages
//!
//! Examples (pseudocode):
//!
//! ```ignore
//! // generate a key package and print base64
//! let kp_b64 = gen_kp_base64(&provider, ciphersuite)?;
//! println!("{}", kp_b64);
//!
//! // create send group from validated key packages provided via stdin
//! let sg = gen_send_group(&mut provider, ciphersuite)?;
//! let welcome_b64 = force_add_members_base64(&provider, &mut sg, &kps)?;
//! println!("{}", welcome_b64);
//! ```

use super::provider::DmlsProvider;
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use core::error::Error;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{
        ApplicationMessage, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessage,
        ProtocolMessage,
    },
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedCommit, StagedWelcome},
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    messages::{
        Welcome,
        proposals::{PreSharedKeyProposal, Proposal},
    },
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
};
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};
use tls_codec::{Deserialize, Serialize};

/// Inject queued exporter PSK proposals into the current send-group and return the
/// resulting commit as a base64-encoded MLS message blob.
///
/// This convenience function loads the local send-group, creates any required commit
/// that injects queued PSK proposals, merges the commit into the group, and returns
/// the serialized commit as a base64 string suitable for piping to other processes.
///
/// Example:
///
/// ```ignore
/// let commit_b64 = send_group_inject_psks_base64(&mut provider, ciphersuite)?;
/// println!("{}", commit_b64);
/// ```
pub fn send_group_inject_psks_base64(
    provider: &mut DmlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<String, Box<dyn Error>> {
    let mut sg = send_group(provider)?;
    inject_psks_base64(provider, &mut sg, ciphersuite)
}

/// Inject queued PSKs into the provided group and return the serialized commit (base64).
///
/// This is the non-lookup variant of `send_group_inject_psks_base64` which accepts a
/// mutable `MlsGroup` reference. It will build and stage a commit containing PSK proposals
/// for all queued exporter PSK ids and return the serialized commit.
///
/// Example:
///
/// ```ignore
/// let mut group = send_group(&provider)?;
/// let commit_b64 = inject_psks_base64(&mut provider, &mut group, ciphersuite)?;
/// println!("{}", commit_b64);
/// ```
pub fn inject_psks_base64(
    provider: &mut DmlsProvider,
    group: &mut MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<String, Box<dyn Error>> {
    Ok(Base64.encode(inject_psks(provider, group, ciphersuite)?.tls_serialize_detached()?))
}

/// Inject queued PSKs into the provided group and return the staged commit message.
///
/// This returns an `MlsMessageOut` which can be serialized and sent on the wire. The
/// commit will be merged into the `group` state before returning.
///
/// Example:
///
/// ```ignore
/// let commit = inject_psks(&mut provider, &mut group, ciphersuite)?;
/// let commit_bytes = commit.tls_serialize_detached()?;
/// ```
pub fn inject_psks(
    provider: &mut DmlsProvider,
    group: &mut MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<MlsMessageOut, Box<dyn Error>> {
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let mut commit_builder = group.commit_builder();
    for psk_id_vec in provider.state_mut().clear_exporter_psk_ids().into_iter() {
        let proposal =
            Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(PreSharedKeyId::new(
                ciphersuite,
                provider.rand(),
                Psk::External(ExternalPsk::new(psk_id_vec)),
            )?)));
        commit_builder = commit_builder.add_proposal(proposal);
    }
    let (commit, _, _) = commit_builder
        .load_psks(provider.storage())?
        .build(provider.rand(), provider.crypto(), provider, |_| true)?
        .stage_commit(provider)?
        .into_messages();
    group.merge_pending_commit(provider)?;
    Ok(commit)
}

/// Derive an exporter PSK from the group's exporter and store it in the local PSK store.
///
/// Returns the PSK identifier (a byte vector) for later injection. The PSK id is constructed
/// from the group's epoch and group id. The derived PSK secret is stored using the OpenMLS
/// PSK storage API so it can be looked up by other operations.
///
/// Example:
///
/// ```ignore
/// let psk_id = store_exporter_psk(&mut provider, &group, ciphersuite, 32)?;
/// // psk_id can be serialized and saved with state if desired
/// ```
pub fn store_exporter_psk(
    provider: &mut DmlsProvider,
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // psk id = epoch + group id
    let mut psk_id_vec = Vec::from(group.epoch().as_u64().to_be_bytes());
    psk_id_vec.extend(group.group_id().to_vec());
    // psk secret
    let psk_secret = group.export_secret(
        provider.crypto(),
        "exporter_psk",
        &psk_id_vec,
        exporter_length,
    )?;
    // store psk
    PreSharedKeyId::new(
        ciphersuite,
        provider.rand(),
        Psk::External(ExternalPsk::new(psk_id_vec.clone())),
    )?
    .store(provider, &psk_secret)?;
    // done; return psk id
    Ok(psk_id_vec)
}

/// Convenience wrapper to deserialize a base64-encoded MLS message from an input line
/// and extract the `MlsMessageBodyIn` variant (Welcome, PublicMessage, PrivateMessage).
///
/// Example:
///
/// ```ignore
/// for line in stdin.lock().lines() {
///     let body = stdin_base64_extract(line)?;
///     match body { ... }
/// }
/// ```
pub fn stdin_base64_extract(
    s: std::io::Result<String>,
) -> Result<MlsMessageBodyIn, Box<dyn Error>> {
    Ok(stdin_base64_to_mls_msg_in(s)?.extract())
}

/// Process a Welcome message and return the joined `MlsGroup` instance.
///
/// A Welcome is produced by a group creator when adding members. This helper creates a
/// `StagedWelcome` and then converts it into an `MlsGroup` (performing necessary validations).
///
/// Example:
///
/// ```ignore
/// let welcome = ...; // Welcome parsed from base64
/// let group = process_welcome(&provider, welcome)?;
/// ```
pub fn process_welcome(
    provider: &DmlsProvider,
    welcome: Welcome,
) -> Result<MlsGroup, Box<dyn Error>> {
    Ok(StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::builder().build(),
        welcome,
        None,
    )?
    .into_group(provider)?)
}

/// Load the local group matching the proto message group id and process the protocol message.
///
/// Returns the group (loaded before processing) and the `ProcessedMessage` result which the
/// caller can inspect to handle application messages or staged commits.
///
/// Example:
///
/// ```ignore
/// let (group, processed) = process_proto_msg(&provider, proto_msg)?;
/// ```
pub fn process_proto_msg(
    provider: &DmlsProvider,
    proto_msg: ProtocolMessage,
) -> Result<(MlsGroup, ProcessedMessage), Box<dyn Error>> {
    match MlsGroup::load(provider.storage(), proto_msg.group_id())? {
        Some(mut g) => {
            let m = g.process_message(provider, proto_msg)?;
            Ok((g, m))
        }
        None => Err("No local group found with the given Group ID".into()),
    }
}

/// Convert an application message payload into a UTF-8 string.
///
/// Panics if the payload is not valid UTF-8; the function returns an `Err` in that case.
///
/// Example:
///
/// ```ignore
/// let s = plaintext(app_msg)?;
/// println!("plaintext: {}", s);
/// ```
pub fn plaintext(app_msg: ApplicationMessage) -> Result<String, Box<dyn Error>> {
    Ok(String::from_utf8(app_msg.into_bytes())?)
}

/// Apply a staged commit to the group and, if the group remains active, store the derived
/// exporter PSK and queue its id for later injection.
///
/// If the commit results in the local leaf being evicted, the group is deleted from storage.
///
/// Example:
///
/// ```ignore
/// apply_commit(&mut provider, &mut group, staged_commit, ciphersuite, 32)?;
/// ```
pub fn apply_commit(
    provider: &mut DmlsProvider,
    group: &mut MlsGroup,
    commit: StagedCommit,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<(), Box<dyn Error>> {
    group.merge_staged_commit(provider, commit)?;
    if group.is_active() {
        // store exporter-psk
        let psk_id_vec = store_exporter_psk(provider, group, ciphersuite, exporter_length)?;
        // enqueue this psk id to be injected on next commit
        provider.state_mut().push_exporter_psk_id(psk_id_vec);
        Ok(())
    } else {
        // delete group if evicted
        group.delete(provider.storage())?;
        Ok(())
    }
}

/// Deserialize a base64-encoded MLS message line into an `MlsMessageIn` instance.
///
/// Example:
///
/// ```ignore
/// let m = stdin_base64_to_mls_msg_in(line)?;
/// ```
pub fn stdin_base64_to_mls_msg_in(
    s: std::io::Result<String>,
) -> Result<MlsMessageIn, Box<dyn Error>> {
    Ok(MlsMessageIn::tls_deserialize_exact(&Base64.decode(s?)?)?)
}

/// Validate and deserialize a base64-encoded KeyPackage provided via stdin.
///
/// The key package is validated using the provider's crypto and the MLS protocol version.
///
/// Example:
///
/// ```ignore
/// let kp = stdin_base64_to_kp(&provider, line)?;
/// ```
pub fn stdin_base64_to_kp(
    provider: &DmlsProvider,
    s: std::io::Result<String>,
) -> Result<KeyPackage, Box<dyn Error>> {
    Ok(KeyPackageIn::tls_deserialize_exact(&Base64.decode(s?)?)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)?)
}

/// Build a minimal `CredentialWithKey` from the provider's signature public key.
///
/// The credential identity used here is the first 8 bytes of the signature public key. This
/// is sufficient for the examples in this crate but not suitable for production identity
/// management.
///
/// Example:
///
/// ```ignore
/// let cred = cred_with_key(&provider);
/// ```
pub fn cred_with_key(provider: &DmlsProvider) -> CredentialWithKey {
    // credential identity is just first 8 bytes of public key
    let signature_public_key = provider.state().signature_key_pair().public_key_raw();
    CredentialWithKey {
        credential: BasicCredential::new(signature_public_key[..8].to_vec()).into(),
        signature_key: signature_public_key.into(),
    }
}
/*
pub fn stdin_create_message_in_send_group_base64(
    provider: &DmlsProvider,
    s: std::io::Result<String>,
) -> Result<String, Box<dyn Error>> {
    stdin_create_message_base64(provider, &mut send_group(provider)?, s)
}
*/
/// Create an MLS application message from a plaintext line and return it as base64.
///
/// This helper uses the group's state to create an encrypted application message that can
/// be delivered to other members. The returned string is the TLS-serialized `MlsMessageOut`
/// encoded in base64.
///
/// Example:
///
/// ```ignore
/// let msg_b64 = stdin_create_message_base64(&provider, &mut group, Ok("Hello".to_string()))?;
/// println!("{}", msg_b64);
/// ```
pub fn stdin_create_message_base64(
    provider: &DmlsProvider,
    group: &mut MlsGroup,
    s: std::io::Result<String>,
) -> Result<String, Box<dyn Error>> {
    Ok(Base64.encode(create_message(provider, group, s?.as_bytes())?.tls_serialize_detached()?))
}

/// Directly create an `MlsMessageOut` application message from raw plaintext bytes.
///
/// This is the lower-level primitive behind `stdin_create_message_base64` and returns the
/// `MlsMessageOut` ready for serialization.
///
/// Example:
///
/// ```ignore
/// let msg = create_message(&provider, &mut group, b"Hello")?;
/// ```
pub fn create_message(
    provider: &DmlsProvider,
    group: &mut MlsGroup,
    plaintext: &[u8],
) -> Result<MlsMessageOut, Box<dyn Error>> {
    Ok(group.create_message(provider, provider, plaintext)?)
}

/// Force-add the provided key packages to the group (no update) and return the Welcome as base64.
///
/// This helper uses `add_members_without_update` so the creator can add members and emit a
/// Welcome for them to join. The Welcome blob is returned as a base64 string that can be
/// distributed to new members.
///
/// Example:
///
/// ```ignore
/// let welcome_b64 = force_add_members_base64(&provider, &mut group, &kps)?;
/// println!("{}", welcome_b64);
/// ```
pub fn force_add_members_base64(
    provider: &DmlsProvider,
    group: &mut MlsGroup,
    kps: &[KeyPackage],
) -> Result<String, Box<dyn Error>> {
    Ok(Base64.encode(force_add_members(provider, group, kps)?.tls_serialize_detached()?))
}

/// Force-add the provided key packages and return the `MlsMessageOut` Welcome message.
///
/// The caller should serialize this message and deliver it to the joiner(s) who will call
/// `process_welcome` to convert it into a group instance.
///
/// Example:
///
/// ```ignore
/// let welcome = force_add_members(&provider, &mut group, &kps)?;
/// ```
pub fn force_add_members(
    provider: &DmlsProvider,
    group: &mut MlsGroup,
    kps: &[KeyPackage],
) -> Result<MlsMessageOut, Box<dyn Error>> {
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let (_, welcome, _) = group.add_members_without_update(provider, provider, kps)?;
    group.merge_pending_commit(provider)?;
    Ok(welcome)
}

/// Return the current send-group (the group's id stored in `DmlsState`) loaded from storage.
///
/// Returns an error if no send-group id is set or if the group cannot be loaded.
///
/// Example:
///
/// ```ignore
/// let group = send_group(&provider)?;
/// ```
pub fn send_group(provider: &DmlsProvider) -> Result<MlsGroup, Box<dyn Error>> {
    match provider.state().send_group_id() {
        None => Err("No send group exists".into()),
        Some(send_group_id) => Ok(MlsGroup::load(provider.storage(), &send_group_id)?.unwrap()),
    }
}

/// Create a new send-group and persist its id to state. Returns an error if a send-group already exists.
///
/// This function sets `send_group_id` in the provider state so subsequent calls to `send_group`
/// will return the correct group instance.
///
/// Example:
///
/// ```ignore
/// let sg = gen_send_group(&mut provider, ciphersuite)?;
/// ```
pub fn gen_send_group(
    provider: &mut DmlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<MlsGroup, Box<dyn Error>> {
    match provider.state().send_group_id() {
        None => {
            let group = MlsGroup::new(
                provider,
                provider,
                &MlsGroupCreateConfig::builder()
                    .ciphersuite(ciphersuite)
                    .use_ratchet_tree_extension(true)
                    .build(),
                cred_with_key(provider),
            )?;
            provider
                .state_mut()
                .set_send_group_id(group.group_id().clone());
            Ok(group)
        }
        Some(_) => Err("Send group already exists".into()),
    }
}

/// Force a self-update (rekey) in the send-group and return the staged commit as base64.
///
/// The function also stores the derived exporter PSK to the PSK store.
///
/// Example:
///
/// ```ignore
/// let commit_b64 = send_group_update_base64(&mut provider, ciphersuite, 32)?;
/// ```
pub fn send_group_update_base64(
    provider: &mut DmlsProvider,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<String, Box<dyn Error>> {
    let mut sg = send_group(provider)?;
    let commit = force_self_update_base64(provider, &mut sg, ciphersuite, exporter_length)?;
    // store exporter psk
    drop(store_exporter_psk(
        provider,
        &sg,
        ciphersuite,
        exporter_length,
    )?);
    // done
    Ok(commit)
}

/// Force a self-update and return the serialized commit (base64).
///
/// This performs a local self-update and stages & merges the commit into the group.
///
/// Example:
///
/// ```ignore
/// let commit = force_self_update_base64(&mut provider, &mut group, ciphersuite, 32)?;
/// ```
pub fn force_self_update_base64(
    provider: &mut DmlsProvider,
    group: &mut MlsGroup,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<String, Box<dyn Error>> {
    Ok(Base64.encode(
        force_self_update(provider, group, ciphersuite, exporter_length)?
            .tls_serialize_detached()?,
    ))
}

/// Force a self-update and return the staged commit message.
///
/// The commit is produced by calling `self_update` on the group, staged, merged, and its
/// corresponding exporter PSK will be stored. The resulting `MlsMessageOut` should be sent
/// to other group members to finalize the update.
///
/// Example:
///
/// ```ignore
/// let staged_commit = force_self_update(&mut provider, &mut group, ciphersuite, 32)?;
/// ```
pub fn force_self_update(
    provider: &mut DmlsProvider,
    group: &mut MlsGroup,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<MlsMessageOut, Box<dyn Error>> {
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let (commit, _, _) = group
        .self_update(provider, provider, LeafNodeParameters::builder().build())?
        .into_messages();
    group.merge_pending_commit(provider)?;
    drop(store_exporter_psk(
        provider,
        group,
        ciphersuite,
        exporter_length,
    )?);
    Ok(commit)
}

/// Generate a KeyPackage for the provider's credential and return it as a base64 blob.
///
/// KeyPackages are used when adding members to MLS groups; the producer of a KeyPackage
/// should distribute the base64 string to the group creator who will validate and include it.
///
/// Example:
///
/// ```ignore
/// let kp_b64 = gen_kp_base64(&provider, ciphersuite)?;
/// println!("{}", kp_b64);
/// ```
pub fn gen_kp_base64(
    provider: &DmlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<String, Box<dyn Error>> {
    Ok(Base64.encode(
        KeyPackage::builder()
            .build(ciphersuite, provider, provider, cred_with_key(provider))?
            .key_package()
            .clone()
            .tls_serialize_detached()?,
    ))
}
