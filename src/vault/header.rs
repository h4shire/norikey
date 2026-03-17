use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    config::{HashProfile, LocalConfig, RemoteServerConfig, RngMode},
    policy::{FactorKind, ThresholdPolicy},
    vault::{
        crypto::{generate_nonce, generate_salt},
        secret::{ContainerKey, NONCE_LEN, SALT_LEN},
    },
};

pub const CONTAINER_MAGIC: &[u8; 8] = b"NORIKEY1";
pub const HEADER_FORMAT: &str = "norikey-header-v1";
pub const HEADER_PROFILE: &str = "resilient-secret-recovery";
pub const HEADER_MAC_BLAKE3_KEYED: &str = "blake3-keyed-v1";
pub const HEADER_MAC_SHA3_KMAC256: &str = "sha3-kmac256-v1";
pub const PAYLOAD_CIPHER_AES256_GCM_V1: &str = "aes256-gcm-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBinding {
    pub factor: FactorKind,
    pub share_id: u8,
    pub locator: Option<String>,
    #[serde(default = "default_share_protection")]
    pub protection: String,
    pub wrapped_share_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityPolicy {
    #[serde(default = "default_header_mac_algorithm")]
    pub header_mac_algorithm: String,
    #[serde(default)]
    pub header_mac_hex: String,
    #[serde(default = "default_true")]
    pub aad_binding: bool,
    #[serde(default = "default_header_canonicalization")]
    pub canonicalization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyPolicy {
    #[serde(default = "default_rng_mode_string")]
    pub rng_mode: String,
    #[serde(default = "default_true")]
    pub os_rng_required: bool,
    #[serde(default)]
    pub external_entropy_required: bool,
    #[serde(default = "default_external_entropy_mode")]
    pub external_entropy_mode: String,
    #[serde(default = "default_external_entropy_min_bytes")]
    pub external_entropy_min_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServerEntry {
    pub id: String,
    pub endpoint: String,
    #[serde(default = "default_remote_weight")]
    pub weight: u32,
    #[serde(default)]
    pub response_sig_key_id: Option<String>,
    #[serde(default)]
    pub response_sig_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteQuorumPolicy {
    pub group_id: String,
    pub required: bool,
    pub quorum_k: u8,
    pub quorum_n: u8,
    #[serde(default = "default_selection_mode")]
    pub selection_mode: String,
    #[serde(default = "default_remote_max_active_servers")]
    pub max_active_servers: u8,
    #[serde(default = "default_remote_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_remote_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    #[serde(default = "default_true")]
    pub require_brain_key_auth: bool,
    #[serde(default = "default_remote_auth_mode")]
    pub auth_mode: String,
    #[serde(default = "default_remote_release_mode")]
    pub release_mode: String,
    #[serde(default = "default_true")]
    pub require_distinct_servers: bool,
    #[serde(default)]
    pub server_pool: Vec<RemoteServerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadPolicy {
    #[serde(default = "default_payload_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub nonce_hex: String,
    #[serde(default = "default_true")]
    pub aad_binding: bool,
    #[serde(default)]
    pub ciphertext_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHeader {
    pub format: String,
    pub version: u32,
    #[serde(default = "default_header_profile")]
    pub profile: String,
    pub policy: ThresholdPolicy,
    pub argon_iterations: u32,
    pub argon_memory_kib: u32,
    #[serde(default = "default_hash_profile_string")]
    pub hash_profile: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    #[serde(default)]
    pub integrity: IntegrityPolicy,
    #[serde(default)]
    pub entropy: EntropyPolicy,
    #[serde(default)]
    pub share_bindings: Vec<ShareBinding>,
    #[serde(default)]
    pub remote_quorum: Option<RemoteQuorumPolicy>,
    #[serde(default)]
    pub remote_gate_binding: Option<ShareBinding>,
    #[serde(default)]
    pub payload: Option<PayloadPolicy>,
}

impl ContainerHeader {
    pub fn from_config(policy: ThresholdPolicy, config: &LocalConfig) -> Result<Self> {
        if matches!(config.hash_profile, HashProfile::Sha3Kmac256) {
            bail!(
                "hash profile '{}' is declared but not implemented for header integrity yet",
                HashProfile::Sha3Kmac256.as_str()
            );
        }

        let salt = generate_salt();
        let nonce = generate_nonce();
        let hash_profile = config.hash_profile.as_str().to_string();
        let integrity = IntegrityPolicy {
            header_mac_algorithm: HEADER_MAC_BLAKE3_KEYED.to_string(),
            header_mac_hex: String::new(),
            aad_binding: true,
            canonicalization: default_header_canonicalization(),
        };
        let entropy = EntropyPolicy {
            rng_mode: config.rng_mode.as_str().to_string(),
            os_rng_required: config.os_rng_required,
            external_entropy_required: config.external_entropy_required,
            external_entropy_mode: config.external_entropy_mode.clone(),
            external_entropy_min_bytes: config.external_entropy_min_bytes,
        };

        Ok(Self {
            format: HEADER_FORMAT.to_string(),
            version: 1,
            profile: HEADER_PROFILE.to_string(),
            policy,
            argon_iterations: config.argon_iterations,
            argon_memory_kib: config.argon_memory,
            hash_profile,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            integrity,
            entropy,
            share_bindings: Vec::new(),
            remote_quorum: build_remote_quorum(config),
            remote_gate_binding: None,
            payload: None,
        })
    }

    pub fn prepare_payload_metadata(&mut self, plaintext_len: usize) {
        let nonce = generate_nonce();
        self.payload = Some(PayloadPolicy {
            cipher: PAYLOAD_CIPHER_AES256_GCM_V1.to_string(),
            nonce_hex: hex::encode(nonce),
            aad_binding: true,
            ciphertext_len: plaintext_len as u64 + 16,
        });
    }

    pub fn payload_nonce_bytes(&self) -> Result<[u8; NONCE_LEN]> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("container header does not contain payload metadata"))?;
        decode_fixed_hex::<NONCE_LEN>(&payload.nonce_hex, "payload nonce")
    }

    pub fn payload_aad_bytes(&self) -> Result<Vec<u8>> {
        serde_yaml::to_string(self)
            .context("failed to serialize header for payload AAD")
            .map(|s| s.into_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;

        if self.format != HEADER_FORMAT {
            bail!(
                "unsupported header format '{}', expected '{}'",
                self.format,
                HEADER_FORMAT
            );
        }

        if self.profile != HEADER_PROFILE {
            bail!(
                "unsupported header profile '{}', expected '{}'",
                self.profile,
                HEADER_PROFILE
            );
        }

        let _ = self.salt_bytes().context("invalid salt in container header")?;
        let _ = self.nonce_bytes().context("invalid nonce in container header")?;

        if self.hash_profile != HashProfile::Blake3.as_str()
            && self.hash_profile != HashProfile::Sha3Kmac256.as_str()
        {
            bail!("unsupported hash profile '{}'", self.hash_profile);
        }

        if self.hash_profile == HashProfile::Sha3Kmac256.as_str() {
            bail!(
                "hash profile '{}' is declared but not implemented for header integrity yet",
                self.hash_profile
            );
        }

        if self.integrity.header_mac_algorithm != HEADER_MAC_BLAKE3_KEYED
            && self.integrity.header_mac_algorithm != HEADER_MAC_SHA3_KMAC256
        {
            bail!(
                "unsupported header MAC algorithm '{}'",
                self.integrity.header_mac_algorithm
            );
        }

        if self.integrity.header_mac_algorithm == HEADER_MAC_SHA3_KMAC256 {
            bail!(
                "header MAC algorithm '{}' is declared but not wired yet",
                self.integrity.header_mac_algorithm
            );
        }

        if !self.share_bindings.is_empty() {
            if self.share_bindings.len() != self.policy.enabled_factors.len() {
                bail!(
                    "share binding count {} does not match enabled factor count {}",
                    self.share_bindings.len(),
                    self.policy.enabled_factors.len()
                );
            }

            for (idx, binding) in self.share_bindings.iter().enumerate() {
                let expected_factor = self.policy.enabled_factors[idx];
                if binding.factor != expected_factor {
                    bail!(
                        "share binding {} belongs to '{}' but expected '{}'",
                        idx,
                        binding.factor.as_str(),
                        expected_factor.as_str()
                    );
                }
            }
        }

        if let Some(remote) = &self.remote_quorum {
            if remote.quorum_k == 0 || remote.quorum_n == 0 {
                bail!("remote quorum values must be greater than zero");
            }
            if remote.quorum_k > remote.quorum_n {
                bail!(
                    "remote quorum_k {} exceeds quorum_n {}",
                    remote.quorum_k,
                    remote.quorum_n
                );
            }
            if remote.server_pool.is_empty() {
                bail!("remote_quorum is present but server_pool is empty");
            }
            if remote.server_pool.len() < remote.quorum_n as usize {
                bail!(
                    "remote quorum_n {} exceeds configured remote server count {}",
                    remote.quorum_n,
                    remote.server_pool.len()
                );
            }
            if remote.max_active_servers < remote.quorum_k {
                bail!(
                    "remote max_active_servers {} must be >= quorum_k {}",
                    remote.max_active_servers,
                    remote.quorum_k
                );
            }
        }

        if let Some(binding) = &self.remote_gate_binding {
            if binding.factor != FactorKind::RemoteShare {
                bail!("remote_gate_binding must use factor 'remote_share'");
            }
            if self.remote_quorum.is_none() {
                bail!("remote_gate_binding is present but remote_quorum metadata is missing");
            }
        }

        if self.remote_gate_binding.is_some() && self.policy.enabled_factors.contains(&FactorKind::RemoteShare) {
            bail!("container mixes legacy remote_share threshold mode with remote_gate mode");
        }

        if self.remote_quorum.as_ref().map(|q| q.required).unwrap_or(false)
            && !self.policy.enabled_factors.contains(&FactorKind::RemoteShare)
            && self.remote_gate_binding.is_none()
        {
            bail!("remote_quorum is required but remote_gate_binding is missing");
        }

        if let Some(payload) = &self.payload {
            if payload.cipher != PAYLOAD_CIPHER_AES256_GCM_V1 {
                bail!("unsupported payload cipher '{}'", payload.cipher);
            }
            let _ = self.payload_nonce_bytes().context("invalid payload nonce in container header")?;
        }

        Ok(())
    }

    pub fn refresh_integrity(&mut self, container_key: &ContainerKey) -> Result<()> {
        let mac = self.compute_header_mac(container_key)?;
        self.integrity.header_mac_hex = hex::encode(mac);
        Ok(())
    }

    pub fn verify_integrity(&self, container_key: &ContainerKey) -> Result<()> {
        if self.integrity.header_mac_hex.is_empty() {
            bail!("container header integrity tag is missing");
        }
        let expected = self.compute_header_mac(container_key)?;
        let actual = hex::decode(&self.integrity.header_mac_hex)
            .context("container header integrity tag is not valid hex")?;
        if expected.as_slice() != actual.as_slice() {
            bail!("container header integrity verification failed");
        }
        Ok(())
    }

    pub fn salt_bytes(&self) -> Result<[u8; SALT_LEN]> {
        decode_fixed_hex::<SALT_LEN>(&self.salt_hex, "salt")
    }

    pub fn nonce_bytes(&self) -> Result<[u8; NONCE_LEN]> {
        decode_fixed_hex::<NONCE_LEN>(&self.nonce_hex, "nonce")
    }

    fn compute_header_mac(&self, container_key: &ContainerKey) -> Result<[u8; 32]> {
        match self.integrity.header_mac_algorithm.as_str() {
            HEADER_MAC_BLAKE3_KEYED => {
                let bytes = self.canonical_bytes_for_integrity()?;
                let digest = blake3::keyed_hash(container_key.as_bytes(), &bytes);
                Ok(*digest.as_bytes())
            }
            HEADER_MAC_SHA3_KMAC256 => {
                bail!("header MAC algorithm '{}' is declared but not wired yet", HEADER_MAC_SHA3_KMAC256)
            }
            other => bail!("unsupported header MAC algorithm '{}'", other),
        }
    }

    fn canonical_bytes_for_integrity(&self) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.integrity.header_mac_hex.clear();
        serde_yaml::to_string(&canonical)
            .context("failed to canonicalize header for integrity binding")
            .map(|s| s.into_bytes())
    }
}

pub fn write_container(path: &Path, header: &ContainerHeader, payload: &[u8]) -> Result<()> {
    let header_bytes = serde_yaml::to_string(header)
        .context("failed to serialize container header")?
        .into_bytes();

    if header_bytes.len() > u32::MAX as usize {
        bail!("header is too large to fit into the phase-1 container envelope");
    }

    let mut file = File::create(path).with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(CONTAINER_MAGIC)?;
    file.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    file.write_all(&header_bytes)?;
    file.write_all(payload)?;
    Ok(())
}

pub fn read_container(path: &Path) -> Result<(ContainerHeader, Vec<u8>)> {
    let mut file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != CONTAINER_MAGIC {
        bail!("file does not start with a NoriKey magic header");
    }

    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let header_len = u32::from_be_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)?;

    let header: ContainerHeader =
        serde_yaml::from_slice(&header_bytes).context("failed to parse container header")?;
    header.validate()?;

    let mut payload = Vec::new();
    file.read_to_end(&mut payload)?;

    Ok((header, payload))
}

pub fn read_header_from_container(path: &Path) -> Result<ContainerHeader> {
    read_container(path).map(|(header, _)| header)
}

fn build_remote_quorum(config: &LocalConfig) -> Option<RemoteQuorumPolicy> {
    if !config.remote_gate_enabled() {
        return None;
    }

    let servers = config.resolved_remote_servers();
    if servers.is_empty() {
        return None;
    }

    let quorum_n = servers.len().min(u8::MAX as usize) as u8;
    let quorum_k = config.remote_quorum_k.min(quorum_n).max(1);

    Some(RemoteQuorumPolicy {
        group_id: "remote-quorum-1".to_string(),
        required: true,
        quorum_k,
        quorum_n,
        selection_mode: config.remote_selection_mode.clone(),
        max_active_servers: config.remote_max_active_servers.min(quorum_n).max(1),
        request_timeout_ms: config.remote_request_timeout_ms,
        retry_backoff_ms: config.remote_retry_backoff_ms,
        require_brain_key_auth: config.remote_require_brain_key_auth,
        auth_mode: config.remote_auth_mode.clone(),
        release_mode: config.remote_release_mode.clone(),
        require_distinct_servers: config.remote_require_distinct_servers,
        server_pool: servers.into_iter().map(RemoteServerEntry::from).collect(),
    })
}

impl From<RemoteServerConfig> for RemoteServerEntry {
    fn from(value: RemoteServerConfig) -> Self {
        Self {
            id: value.id,
            endpoint: value.endpoint,
            weight: value.weight,
            response_sig_key_id: value.response_sig_key_id,
            response_sig_pubkey_hex: value.response_sig_pubkey_hex,
        }
    }
}

impl Default for IntegrityPolicy {
    fn default() -> Self {
        Self {
            header_mac_algorithm: default_header_mac_algorithm(),
            header_mac_hex: String::new(),
            aad_binding: true,
            canonicalization: default_header_canonicalization(),
        }
    }
}

impl Default for EntropyPolicy {
    fn default() -> Self {
        Self {
            rng_mode: default_rng_mode_string(),
            os_rng_required: true,
            external_entropy_required: false,
            external_entropy_mode: default_external_entropy_mode(),
            external_entropy_min_bytes: default_external_entropy_min_bytes(),
        }
    }
}

fn default_share_protection() -> String { "plain".to_string() }
fn default_header_profile() -> String { HEADER_PROFILE.to_string() }
fn default_header_mac_algorithm() -> String { HEADER_MAC_BLAKE3_KEYED.to_string() }
fn default_header_canonicalization() -> String { "yaml-c14n-v1".to_string() }
fn default_hash_profile_string() -> String { HashProfile::Blake3.as_str().to_string() }
fn default_rng_mode_string() -> String { RngMode::Standard.as_str().to_string() }
fn default_external_entropy_mode() -> String { "mix".to_string() }
const fn default_external_entropy_min_bytes() -> u32 { 64 }
fn default_selection_mode() -> String { "random_subset".to_string() }
const fn default_remote_max_active_servers() -> u8 { 2 }
const fn default_remote_request_timeout_ms() -> u64 { 3500 }
const fn default_remote_retry_backoff_ms() -> u64 { 1200 }
fn default_remote_auth_mode() -> String { "opaque".to_string() }
fn default_remote_release_mode() -> String { "share".to_string() }
const fn default_remote_weight() -> u32 { 100 }
fn default_payload_cipher() -> String { PAYLOAD_CIPHER_AES256_GCM_V1.to_string() }
const fn default_true() -> bool { true }

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;

    if decoded.len() != N {
        bail!(
            "{label} must be {expected} bytes ({expected_hex} hex chars), got {actual} bytes",
            expected = N,
            expected_hex = N * 2,
            actual = decoded.len()
        );
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}
