use std::{env, process::Command};
#[cfg(target_os = "linux")]
use std::fs;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};

use crate::{
    config::LocalConfig,
    policy::FactorKind,
    vault::{
        header::{ContainerHeader, ShareBinding},
        secret::{CONTAINER_KEY_LEN, NONCE_LEN},
        share::SecretShare,
    },
};

use super::{decode_wrapped_share, FactorProvider, PROTECTION_HARDWARE_ID_AEAD, PROTECTION_PLAIN};

const NONCE_CONTEXT: &[u8] = b"norikey/v1/hardware-id-share-nonce";
const KEY_CONTEXT: &[u8] = b"norikey/v1/hardware-id-wrapping-key";
const LOCATOR: &str = "machine-bound";

pub struct HardwareIdProvider;

impl FactorProvider for HardwareIdProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::HardwareId
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        header: &ContainerHeader,
        _config: &LocalConfig,
    ) -> Result<ShareBinding> {
        let hardware_id = read_hardware_id()
            .context("failed to read local hardware identifier for share protection")?;
        let wrapping_key = derive_wrapping_key(&hardware_id, header)
            .context("failed to derive wrapping key from local hardware identifier")?;
        let binding_nonce = derive_binding_nonce(header, share_id)
            .context("failed to derive deterministic binding nonce for hardware-id wrapping")?;

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
            .map_err(|_| anyhow!("failed to initialize AES-256-GCM for hardware-id share wrapping"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&binding_nonce), share.as_bytes())
            .map_err(|_| anyhow!("failed to encrypt share with hardware identifier"))?;

        Ok(ShareBinding {
            factor: self.kind(),
            share_id,
            locator: Some(LOCATOR.to_string()),
            protection: PROTECTION_HARDWARE_ID_AEAD.to_string(),
            wrapped_share_hex: Some(hex::encode(ciphertext)),
        })
    }

    fn collect_share(
        &self,
        binding: &ShareBinding,
        header: &ContainerHeader,
        _config: &LocalConfig,
    ) -> Result<Option<SecretShare>> {
        if binding.factor != self.kind() {
            return Ok(None);
        }

        match binding.protection.as_str() {
            PROTECTION_PLAIN => decode_wrapped_share(binding),
            PROTECTION_HARDWARE_ID_AEAD => {
                let ciphertext = match &binding.wrapped_share_hex {
                    Some(hex_blob) => hex::decode(hex_blob)
                        .with_context(|| "hardware-id binding does not contain valid ciphertext hex")?,
                    None => return Ok(None),
                };

                let hardware_id = read_hardware_id()
                    .context("failed to read local hardware identifier for share recovery")?;
                let wrapping_key = derive_wrapping_key(&hardware_id, header)
                    .context("failed to derive wrapping key from local hardware identifier")?;
                let binding_nonce = derive_binding_nonce(header, binding.share_id)
                    .context("failed to derive deterministic binding nonce for hardware-id unwrap")?;

                let cipher = Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| {
                    anyhow!("failed to initialize AES-256-GCM for hardware-id share unwrap")
                })?;
                let plaintext = cipher
                    .decrypt(Nonce::from_slice(&binding_nonce), ciphertext.as_ref())
                    .map_err(|_| anyhow!("failed to decrypt share with this machine's hardware identifier"))?;

                Ok(Some(SecretShare::from_bytes(plaintext)))
            }
            other => bail!(
                "hardware-id provider does not support share protection '{}'",
                other
            ),
        }
    }
}

fn derive_wrapping_key(hardware_id: &str, header: &ContainerHeader) -> Result<[u8; CONTAINER_KEY_LEN]> {
    let salt = header
        .salt_bytes()
        .context("container header has invalid salt for hardware-id derivation")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_CONTEXT);
    hasher.update(&salt);
    hasher.update(hardware_id.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; CONTAINER_KEY_LEN];
    out.copy_from_slice(&digest.as_bytes()[..CONTAINER_KEY_LEN]);
    Ok(out)
}

fn derive_binding_nonce(header: &ContainerHeader, share_id: u8) -> Result<[u8; NONCE_LEN]> {
    let base_nonce = header
        .nonce_bytes()
        .context("container header has invalid nonce for hardware-id binding")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(NONCE_CONTEXT);
    hasher.update(&base_nonce);
    hasher.update(&[share_id]);
    let digest = hasher.finalize();

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    Ok(nonce)
}

fn read_hardware_id() -> Result<String> {
    if let Ok(value) = env::var("NORIKEY_HARDWARE_ID") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    read_platform_hardware_id()
}

#[cfg(target_os = "linux")]
fn read_platform_hardware_id() -> Result<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(raw) = fs::read_to_string(path) {
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }

    bail!("could not read a non-empty machine-id from /etc/machine-id or /var/lib/dbus/machine-id")
}

#[cfg(target_os = "macos")]
fn read_platform_hardware_id() -> Result<String> {
    let output = Command::new("sysctl")
        .args(["-n", "kern.uuid"])
        .output()
        .context("failed to invoke sysctl to obtain kern.uuid")?;

    if !output.status.success() {
        bail!("sysctl -n kern.uuid did not exit successfully");
    }

    let value = String::from_utf8(output.stdout)
        .context("sysctl output for kern.uuid was not valid UTF-8")?
        .trim()
        .to_string();

    if value.is_empty() {
        bail!("kern.uuid was empty");
    }

    Ok(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_platform_hardware_id() -> Result<String> {
    bail!(
        "hardware-id factor is not implemented for this platform; set NORIKEY_HARDWARE_ID to override for testing"
    )
}
