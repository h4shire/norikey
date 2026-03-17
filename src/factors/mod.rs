use anyhow::{Context, Result};

use crate::{
    config::LocalConfig,
    policy::FactorKind,
    vault::{
        header::{ContainerHeader, ShareBinding},
        share::SecretShare,
    },
};

pub mod brain;
pub mod dead_sector;
pub mod hardware;
pub mod remote;
pub mod stego;
pub mod yubikey;

pub const PROTECTION_PLAIN: &str = "plain";
pub const PROTECTION_BRAIN_KEY_AEAD: &str = "brain_key_argon2id_aes256gcm";
pub const PROTECTION_HARDWARE_ID_AEAD: &str = "hardware_id_blake3_aes256gcm";
pub const PROTECTION_DEAD_SECTOR_RAW: &str = "dead_sector_raw_v1";
pub const PROTECTION_YUBIKEY_A_DEV_AEAD: &str = "yubikey_a_dev_blake3_aes256gcm";
pub const PROTECTION_YUBIKEY_B_DEV_AEAD: &str = "yubikey_b_dev_blake3_aes256gcm";
pub const PROTECTION_YUBIKEY_A_YKMAN_AEAD: &str = "yubikey_a_hmac_sha1_ykman_v1";
pub const PROTECTION_YUBIKEY_B_YKMAN_AEAD: &str = "yubikey_b_hmac_sha1_ykman_v1";
pub const PROTECTION_REMOTE_QUORUM_RELEASE: &str = "remote_quorum_release_v1";

pub trait FactorProvider {
    fn kind(&self) -> FactorKind;

    fn store_share(&self, share_id: u8, share: &SecretShare, header: &ContainerHeader, config: &LocalConfig) -> Result<ShareBinding>;
    fn collect_share(&self, binding: &ShareBinding, header: &ContainerHeader, config: &LocalConfig) -> Result<Option<SecretShare>>;
}

pub fn provider_for(kind: FactorKind) -> Box<dyn FactorProvider> {
    match kind {
        FactorKind::BrainKey => Box::new(brain::BrainKeyProvider),
        FactorKind::HardwareId => Box::new(hardware::HardwareIdProvider),
        FactorKind::DeadSector => Box::new(dead_sector::DeadSectorProvider),
        FactorKind::YubiKeyA | FactorKind::YubiKeyB => Box::new(yubikey::provider_for_yubikey_lane(kind)),
        FactorKind::Steganography => Box::new(stego::StegoProvider),
        FactorKind::RemoteShare => Box::new(remote::RemoteShareProvider),
    }
}

pub fn collect_shares(header: &ContainerHeader, config: &LocalConfig) -> Result<Vec<SecretShare>> {
    let mut shares = Vec::new();
    for binding in &header.share_bindings {
        let provider = provider_for(binding.factor);
        if let Some(share) = provider.collect_share(binding, header, config).with_context(|| format!("failed to collect share for factor '{}'", binding.factor.as_str()))? {
            shares.push(share);
        }
    }
    Ok(shares)
}

pub fn build_share_bindings(factors: &[FactorKind], shares: &[SecretShare], header: &ContainerHeader, config: &LocalConfig) -> Result<Vec<ShareBinding>> {
    if factors.len() != shares.len() {
        anyhow::bail!("factor/share mismatch: {} factors configured, {} shares generated", factors.len(), shares.len());
    }
    let mut bindings = Vec::with_capacity(shares.len());
    for (idx, (factor, share)) in factors.iter().zip(shares.iter()).enumerate() {
        let provider = provider_for(*factor);
        let binding = provider.store_share((idx + 1) as u8, share, header, config)
            .with_context(|| format!("failed to store share {} for factor '{}'", idx + 1, factor.as_str()))?;
        bindings.push(binding);
    }
    Ok(bindings)
}


pub(crate) fn decode_wrapped_share(binding: &ShareBinding) -> Result<Option<SecretShare>> {
    match &binding.wrapped_share_hex {
        Some(hex_share) => {
            let bytes = hex::decode(hex_share).with_context(|| format!("binding for '{}' does not contain valid hex", binding.factor.as_str()))?;
            Ok(Some(SecretShare::from_bytes(bytes)))
        }
        None => Ok(None),
    }
}

