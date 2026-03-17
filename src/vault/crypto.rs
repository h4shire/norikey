use aes_gcm::{
    aead::{Aead, KeyInit, rand_core::RngCore},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use aes_gcm::aead::OsRng;

use crate::vault::secret::{ContainerKey, MasterSecret, MASTER_SECRET_LEN, NONCE_LEN, SALT_LEN};

const CONTAINER_KEY_DERIVE_CONTEXT: &[u8] = b"norikey/v1/container-key";
const CONTAINER_KEY_WITH_REMOTE_GATE_CONTEXT: &[u8] = b"norikey/v1/container-key-remote-gate";

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn generate_master_secret() -> MasterSecret {
    let mut secret = [0u8; MASTER_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    MasterSecret::new(secret)
}

pub fn derive_container_key(secret: &MasterSecret, salt: &[u8; SALT_LEN]) -> ContainerKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTAINER_KEY_DERIVE_CONTEXT);
    hasher.update(secret.as_bytes());
    hasher.update(salt);

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    ContainerKey::new(out)
}

pub fn derive_container_key_with_remote_gate(
    local_secret: &MasterSecret,
    remote_gate_material: &[u8],
    salt: &[u8; SALT_LEN],
) -> ContainerKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTAINER_KEY_WITH_REMOTE_GATE_CONTEXT);
    hasher.update(local_secret.as_bytes());
    hasher.update(remote_gate_material);
    hasher.update(salt);

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    ContainerKey::new(out)
}

pub fn encrypt_payload(
    key: &ContainerKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for payload encryption"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: plaintext, aad },
        )
        .map_err(|_| anyhow!("failed to encrypt payload"))
}

pub fn decrypt_payload(
    key: &ContainerKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for payload decryption"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt payload"))
}
