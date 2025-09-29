use super::provider::DmlsProvider;
use core::error::Error;
use openmls::{
    credentials::{BasicCredential, Credential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        GroupId, MergeCommitError, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        MlsGroupStateError, ProcessMessageError, StagedWelcome,
    },
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    prelude::{Capabilities, LeafNodeIndex},
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
};
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};
use tls_codec::{Deserialize, Serialize};

#[derive(Debug)]
pub struct DmlsAgent {
    provider: DmlsProvider,
    group_config: MlsGroupCreateConfig,
    cred_with_key: CredentialWithKey,
}

#[allow(clippy::from_over_into)]
impl Into<DmlsProvider> for DmlsAgent {
    fn into(self) -> DmlsProvider {
        self.provider
    }
}

impl DmlsAgent {
    pub fn new(provider: DmlsProvider) -> Self {
        // config
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .use_ratchet_tree_extension(true)
            .capabilities(Capabilities::new(
                None,
                None,
                Some(&[ExtensionType::LastResort]),
                None,
                Some(&[CredentialType::Basic]),
            ))
            .build();
        // credential/key... credential identity is just first 7 bytes of public key
        let signature_public_key = provider.state().signature_key_pair().public_key_raw();
        let cred_with_key = CredentialWithKey {
            credential: BasicCredential::new(signature_public_key[..7].to_vec()).into(),
            signature_key: signature_public_key.into(),
        };
        // done
        Self {
            provider,
            group_config,
            cred_with_key,
        }
    }
    pub fn gen_kp(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(MlsMessageOut::from(
            KeyPackage::builder()
                .leaf_node_capabilities(Capabilities::new(
                    None,
                    None,
                    Some(&[ExtensionType::LastResort]),
                    None,
                    Some(&[CredentialType::Basic]),
                ))
                .build(
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    &self.provider,
                    &self.provider,
                    self.cred_with_key.clone(),
                )?
                .key_package()
                .clone(),
        )
        .tls_serialize_detached()?)
    }
}
