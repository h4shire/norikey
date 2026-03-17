use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::{
    config::LocalConfig,
    policy::FactorKind,
    session,
    vault::{
        header::{ContainerHeader, ShareBinding},
        secret::{CONTAINER_KEY_LEN, NONCE_LEN},
        share::SecretShare,
    },
};

use super::{decode_wrapped_share, FactorProvider, PROTECTION_BRAIN_KEY_AEAD, PROTECTION_PLAIN};

const NONCE_CONTEXT: &[u8] = b"norikey/v1/brain-share-nonce";

pub struct BrainKeyProvider;

impl FactorProvider for BrainKeyProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::BrainKey
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<ShareBinding> {
        let passphrase = session::get_or_prompt_brain_key_for_create()?;
        let wrapping_key = derive_wrapping_key(passphrase.as_str(), header, config)
            .context("failed to derive wrapping key from brain key")?;
        let binding_nonce = derive_binding_nonce(header, share_id)
            .context("failed to derive deterministic binding nonce for brain key wrapping")?;

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
            .map_err(|_| anyhow!("failed to initialize AES-256-GCM for brain key share wrapping"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&binding_nonce), share.as_bytes())
            .map_err(|_| anyhow!("failed to encrypt share with brain key"))?;

        Ok(ShareBinding {
            factor: self.kind(),
            share_id,
            locator: None,
            protection: PROTECTION_BRAIN_KEY_AEAD.to_string(),
            wrapped_share_hex: Some(hex::encode(ciphertext)),
        })
    }

    fn collect_share(
        &self,
        binding: &ShareBinding,
        header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<Option<SecretShare>> {
        if binding.factor != self.kind() {
            return Ok(None);
        }

        match binding.protection.as_str() {
            PROTECTION_PLAIN => decode_wrapped_share(binding),
            PROTECTION_BRAIN_KEY_AEAD => {
                let ciphertext = match &binding.wrapped_share_hex {
                    Some(hex_blob) => hex::decode(hex_blob)
                        .with_context(|| "brain key binding does not contain valid ciphertext hex")?,
                    None => return Ok(None),
                };

                let passphrase = session::get_or_prompt_brain_key_for_unlock()?;
                let wrapping_key = derive_wrapping_key(passphrase.as_str(), header, config)
                    .context("failed to derive wrapping key from brain key")?;
                let binding_nonce = derive_binding_nonce(header, binding.share_id)
                    .context("failed to derive deterministic binding nonce for brain key unwrap")?;

                let cipher = Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| {
                    anyhow!("failed to initialize AES-256-GCM for brain key share unwrap")
                })?;
                let plaintext = cipher
                    .decrypt(Nonce::from_slice(&binding_nonce), ciphertext.as_ref())
                    .map_err(|_| anyhow!("failed to decrypt share with provided brain key"))?;

                Ok(Some(SecretShare::from_bytes(plaintext)))
            }
            other => bail!(
                "brain key provider does not support share protection '{}'",
                other
            ),
        }
    }
}

fn derive_wrapping_key(
    passphrase: &str,
    header: &ContainerHeader,
    config: &LocalConfig,
) -> Result<[u8; CONTAINER_KEY_LEN]> {
    let salt = header
        .salt_bytes()
        .context("container header has invalid salt for brain key derivation")?;
    let params = Params::new(config.argon_memory, config.argon_iterations, 1, Some(CONTAINER_KEY_LEN))
        .map_err(|e| anyhow!("invalid Argon2 parameters for brain key derivation: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; CONTAINER_KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow!("argon2id failed while deriving the brain key wrapping key: {e}"))?;
    Ok(out)
}

fn derive_binding_nonce(header: &ContainerHeader, share_id: u8) -> Result<[u8; NONCE_LEN]> {
    let base_nonce = header
        .nonce_bytes()
        .context("container header has invalid nonce for brain key binding")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(NONCE_CONTEXT);
    hasher.update(&base_nonce);
    hasher.update(&[share_id]);
    let digest = hasher.finalize();

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    Ok(nonce)
}
