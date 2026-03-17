use std::{
    env,
    fs,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::policy::FactorKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashProfile {
    #[serde(rename = "blake3")]
    Blake3,
    #[serde(rename = "sha3_kmac256", alias = "sha3-kmac256")]
    Sha3Kmac256,
}

impl HashProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha3Kmac256 => "sha3_kmac256",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RngMode {
    #[serde(rename = "standard")]
    Standard,
    #[serde(rename = "paranoia")]
    Paranoia,
}

impl RngMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Paranoia => "paranoia",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemoteMode {
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "mandatory_gate", alias = "enabled")]
    MandatoryGate,
}

impl RemoteMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MandatoryGate => "mandatory_gate",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum YubiKeyMode {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "ykman")]
    Ykman,
    #[serde(rename = "dev")]
    Dev,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServerConfig {
    pub id: String,
    pub endpoint: String,
    #[serde(default = "default_remote_weight")]
    pub weight: u32,
    #[serde(default)]
    pub response_sig_key_id: Option<String>,
    #[serde(default)]
    pub response_sig_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadSectorPersistTarget {
    ConfigSealed,
    ConfigYaml,
    EphemeralRunOnly,
}

#[derive(Debug, Clone)]
pub struct DeadSectorLocator {
    pub canonical_path: PathBuf,
    pub offset: u64,
    pub display_model: Option<String>,
    pub display_partition: Option<String>,
    pub display_label: Option<String>,
}

impl DeadSectorLocator {
    pub fn display_summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(model) = &self.display_model {
            if !model.trim().is_empty() {
                parts.push(model.trim().to_string());
            }
        }
        if let Some(partition) = &self.display_partition {
            if !partition.trim().is_empty() {
                parts.push(partition.trim().to_string());
            }
        } else if let Some(label) = &self.display_label {
            if !label.trim().is_empty() {
                parts.push(label.trim().to_string());
            }
        }
        if parts.is_empty() { None } else { Some(parts.join(" / ")) }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalConfig {
    #[serde(default = "default_argon_iterations")]
    pub argon_iterations: u32,
    #[serde(default = "default_argon_memory")]
    pub argon_memory: u32,
    #[serde(default = "default_threshold", alias = "sss_threshold")]
    pub threshold: u8,
    #[serde(default = "default_enabled_factors")]
    pub enabled_factors: Vec<FactorKind>,
    #[serde(default = "default_hash_profile")]
    pub hash_profile: HashProfile,
    #[serde(default = "default_rng_mode")]
    pub rng_mode: RngMode,
    #[serde(default = "default_true")]
    pub os_rng_required: bool,
    #[serde(default)]
    pub external_entropy_required: bool,
    #[serde(default = "default_external_entropy_mode")]
    pub external_entropy_mode: String,
    #[serde(default = "default_external_entropy_min_bytes")]
    pub external_entropy_min_bytes: u32,
    #[serde(default)]
    pub dead_sector_device: Option<String>,
    #[serde(default)]
    pub dead_sector_offset: Option<u64>,
    #[serde(default)]
    pub dead_sector_display_model: Option<String>,
    #[serde(default)]
    pub dead_sector_display_partition: Option<String>,
    #[serde(default)]
    pub dead_sector_display_label: Option<String>,
    #[serde(default)]
    pub stego_carrier_png: Option<String>,
    #[serde(default)]
    pub stego_output_png: Option<String>,
    #[serde(default)]
    pub remote_url: Option<String>,
    #[serde(default)]
    pub remote_servers: Vec<RemoteServerConfig>,
    #[serde(default = "default_remote_mode")]
    pub remote_mode: RemoteMode,
    #[serde(default = "default_remote_quorum_k")]
    pub remote_quorum_k: u8,
    #[serde(default = "default_remote_selection_mode")]
    pub remote_selection_mode: String,
    #[serde(default = "default_remote_max_active_servers")]
    pub remote_max_active_servers: u8,
    #[serde(default = "default_remote_request_timeout_ms")]
    pub remote_request_timeout_ms: u64,
    #[serde(default = "default_remote_retry_backoff_ms")]
    pub remote_retry_backoff_ms: u64,
    #[serde(default = "default_true")]
    pub remote_require_brain_key_auth: bool,
    #[serde(default = "default_remote_auth_mode")]
    pub remote_auth_mode: String,
    #[serde(default = "default_remote_release_mode")]
    pub remote_release_mode: String,
    #[serde(default = "default_true")]
    pub remote_require_distinct_servers: bool,
    #[serde(default = "default_yubikey_mode")]
    pub yubikey_mode: YubiKeyMode,
    #[serde(default = "default_yubikey_binary")]
    pub yubikey_binary: String,
    #[serde(default = "default_yubikey_pool_max_active_factors")]
    pub yubikey_pool_max_active_factors: u8,
    #[serde(default = "default_yubikey_a_slot")]
    pub yubikey_a_slot: u8,
    #[serde(default = "default_yubikey_b_slot")]
    pub yubikey_b_slot: u8,
    #[serde(default = "default_true")]
    pub yubikey_require_distinct_devices: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PartialLocalConfig {
    pub argon_iterations: Option<u32>,
    pub argon_memory: Option<u32>,
    pub threshold: Option<u8>,
    pub enabled_factors: Option<Vec<FactorKind>>,
    pub hash_profile: Option<HashProfile>,
    pub rng_mode: Option<RngMode>,
    pub os_rng_required: Option<bool>,
    pub external_entropy_required: Option<bool>,
    pub external_entropy_mode: Option<String>,
    pub external_entropy_min_bytes: Option<u32>,
    pub dead_sector_device: Option<String>,
    pub dead_sector_offset: Option<u64>,
    pub dead_sector_display_model: Option<String>,
    pub dead_sector_display_partition: Option<String>,
    pub dead_sector_display_label: Option<String>,
    pub stego_carrier_png: Option<String>,
    pub stego_output_png: Option<String>,
    pub remote_url: Option<String>,
    pub remote_servers: Option<Vec<RemoteServerConfig>>,
    pub remote_mode: Option<RemoteMode>,
    pub remote_quorum_k: Option<u8>,
    pub remote_selection_mode: Option<String>,
    pub remote_max_active_servers: Option<u8>,
    pub remote_request_timeout_ms: Option<u64>,
    pub remote_retry_backoff_ms: Option<u64>,
    pub remote_require_brain_key_auth: Option<bool>,
    pub remote_auth_mode: Option<String>,
    pub remote_release_mode: Option<String>,
    pub remote_require_distinct_servers: Option<bool>,
    pub yubikey_mode: Option<YubiKeyMode>,
    pub yubikey_binary: Option<String>,
    pub yubikey_pool_max_active_factors: Option<u8>,
    pub yubikey_a_slot: Option<u8>,
    pub yubikey_b_slot: Option<u8>,
    pub yubikey_require_distinct_devices: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedConfigEnvelope {
    pub format: String,
    pub kdf: String,
    pub cipher: String,
    pub argon_iterations: u32,
    pub argon_memory_kib: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            argon_iterations: default_argon_iterations(),
            argon_memory: default_argon_memory(),
            threshold: default_threshold(),
            enabled_factors: default_enabled_factors(),
            hash_profile: default_hash_profile(),
            rng_mode: default_rng_mode(),
            os_rng_required: true,
            external_entropy_required: false,
            external_entropy_mode: default_external_entropy_mode(),
            external_entropy_min_bytes: default_external_entropy_min_bytes(),
            dead_sector_device: None,
            dead_sector_offset: None,
            dead_sector_display_model: None,
            dead_sector_display_partition: None,
            dead_sector_display_label: None,
            stego_carrier_png: None,
            stego_output_png: None,
            remote_url: None,
            remote_servers: Vec::new(),
            remote_mode: default_remote_mode(),
            remote_quorum_k: default_remote_quorum_k(),
            remote_selection_mode: default_remote_selection_mode(),
            remote_max_active_servers: default_remote_max_active_servers(),
            remote_request_timeout_ms: default_remote_request_timeout_ms(),
            remote_retry_backoff_ms: default_remote_retry_backoff_ms(),
            remote_require_brain_key_auth: true,
            remote_auth_mode: default_remote_auth_mode(),
            remote_release_mode: default_remote_release_mode(),
            remote_require_distinct_servers: true,
            yubikey_mode: default_yubikey_mode(),
            yubikey_binary: default_yubikey_binary(),
            yubikey_pool_max_active_factors: default_yubikey_pool_max_active_factors(),
            yubikey_a_slot: default_yubikey_a_slot(),
            yubikey_b_slot: default_yubikey_b_slot(),
            yubikey_require_distinct_devices: true,
        }
    }
}

impl LocalConfig {
    pub fn load_with_sealed(path: Option<&Path>, brain_key: Option<&str>) -> Result<Self> {
        let path = resolve_config_path(path);
        let sealed_path = sealed_path_for(Some(path.as_path()));

        let mut cfg = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("could not read {}", path.display()))?;
            serde_yaml::from_str::<Self>(&raw)
                .with_context(|| format!("could not parse {}", path.display()))?
        } else if sealed_path.exists() {
            Self::default()
        } else {
            return Err(anyhow!("could not read {}", path.display()));
        };

        if sealed_path.exists() {
            let brain_key = brain_key.ok_or_else(|| {
                anyhow!(
                    "local sealed config exists at {} but no password was supplied",
                    sealed_path.display()
                )
            })?;
            let overlay = load_sealed_overlay(&sealed_path, brain_key)
                .with_context(|| format!("failed to decrypt {}", sealed_path.display()))?;
            cfg.apply_partial(overlay);
        }

        Ok(cfg)
    }

    pub fn resolved_remote_servers(&self) -> Vec<RemoteServerConfig> {
        if !self.remote_servers.is_empty() {
            return self.remote_servers.clone();
        }
        match &self.remote_url {
            Some(url) => vec![RemoteServerConfig {
                id: "srv-1".to_string(),
                endpoint: url.clone(),
                weight: default_remote_weight(),
                response_sig_key_id: None,
                response_sig_pubkey_hex: None,
            }],
            None => Vec::new(),
        }
    }

    pub fn remote_gate_enabled(&self) -> bool {
        matches!(self.remote_mode, RemoteMode::MandatoryGate) || self.uses_legacy_remote_factor()
    }

    pub fn uses_legacy_remote_factor(&self) -> bool {
        self.enabled_factors.contains(&FactorKind::RemoteShare)
    }

    pub fn remote_mode_summary(&self) -> &'static str {
        if matches!(self.remote_mode, RemoteMode::MandatoryGate) {
            return self.remote_mode.as_str();
        }
        if self.uses_legacy_remote_factor() {
            return "legacy_remote_share_factor";
        }
        self.remote_mode.as_str()
    }

    pub fn has_remote_servers_configured(&self) -> bool {
        !self.remote_servers.is_empty() || self.remote_url.is_some()
    }

    pub fn validate_remote_signing_metadata(&self) -> Result<()> {
        if !self.remote_gate_enabled() && !self.uses_legacy_remote_factor() {
            return Ok(());
        }

        let servers = self.resolved_remote_servers();
        if servers.is_empty() {
            bail!("remote mode is enabled but no remote servers are configured");
        }

        for server in servers {
            let key_id = server
                .response_sig_key_id
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty());

            let pubkey = server
                .response_sig_pubkey_hex
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty());

            if key_id.is_none() {
                bail!(
                    "remote server '{}' is missing response_sig_key_id in the effective configuration",
                    server.id
                );
            }

            if pubkey.is_none() {
                bail!(
                    "remote server '{}' is missing response_sig_pubkey_hex in the effective configuration",
                    server.id
                );
            }
        }

        Ok(())
    }

    pub fn active_yubikey_factors(&self) -> Vec<FactorKind> {
        self.enabled_factors
            .iter()
            .copied()
            .filter(|factor| factor.is_yubikey_factor())
            .collect()
    }

    pub fn active_yubikey_lanes_with_slots(&self) -> Result<Vec<(FactorKind, u8)>> {
        self.active_yubikey_factors()
            .into_iter()
            .map(|factor| Ok((factor, self.yubikey_preferred_slot(factor)?)))
            .collect()
    }

    pub fn yubikey_preferred_slot(&self, factor: FactorKind) -> Result<u8> {
        match factor {
            FactorKind::YubiKeyA => Ok(self.yubikey_a_slot),
            FactorKind::YubiKeyB => Ok(self.yubikey_b_slot),
            _ => bail!("factor '{}' is not a YubiKey lane", factor.display_name()),
        }
    }

    pub fn validate_yubikey_pool_constraints(&self) -> Result<()> {
        let active = self.active_yubikey_factors();
        if self.yubikey_pool_max_active_factors == 0 {
            bail!("yubikey_pool_max_active_factors must be at least 1");
        }
        if self.yubikey_pool_max_active_factors > 2 {
            bail!("yubikey_pool_max_active_factors may not exceed 2 in the current YubiKey lane model");
        }
        if active.len() > self.yubikey_pool_max_active_factors as usize {
            bail!(
                "{} YubiKey factors are enabled but yubikey_pool_max_active_factors is {}",
                active.len(),
                self.yubikey_pool_max_active_factors
            );
        }
        Ok(())
    }

    pub fn yubikey_pool_summary(&self) -> String {
        let active = self.active_yubikey_factors();
        let lanes = active
            .iter()
            .filter_map(|factor| factor.yubikey_lane_label())
            .collect::<Vec<_>>()
            .join(", ");
        if lanes.is_empty() {
            format!("disabled (max_active={})", self.yubikey_pool_max_active_factors)
        } else {
            format!(
                "active lanes: {} (max_active={})",
                lanes,
                self.yubikey_pool_max_active_factors
            )
        }
    }

    pub fn yubikey_lane_plan_summary(&self) -> Result<Vec<String>> {
        self.active_yubikey_lanes_with_slots()?
            .into_iter()
            .map(|(factor, slot)| {
                let label = factor.yubikey_lane_label().unwrap_or(factor.as_str());
                Ok(format!("{} -> configured default slot {}", label, slot))
            })
            .collect()
    }

    pub fn resolved_dead_sector_locator(&self) -> Option<DeadSectorLocator> {
        if let (Some(device), Some(offset)) = (self.dead_sector_device.as_ref(), self.dead_sector_offset) {
            let path = normalize_dead_sector_path(Path::new(device));
            let discovered = discover_dead_sector_display(&path);
            return Some(DeadSectorLocator {
                canonical_path: path,
                offset,
                display_model: self
                    .dead_sector_display_model
                    .clone()
                    .or_else(|| discovered.as_ref().and_then(|d| d.display_model.clone())),
                display_partition: self
                    .dead_sector_display_partition
                    .clone()
                    .or_else(|| discovered.as_ref().and_then(|d| d.display_partition.clone())),
                display_label: self
                    .dead_sector_display_label
                    .clone()
                    .or_else(|| discovered.as_ref().and_then(|d| d.display_label.clone())),
            });
        }

        ephemeral_dead_sector_locator_from_env()
    }
    pub fn resolved_stego_carrier_path(&self) -> Option<PathBuf> {
        self.stego_carrier_png
            .as_ref()
            .map(|value| normalize_dead_sector_path(Path::new(value)))
    }

    pub fn resolved_stego_output_path(&self) -> Option<PathBuf> {
        match &self.stego_output_png {
            Some(value) => Some(normalize_dead_sector_path(Path::new(value))),
            None => self
                .resolved_stego_carrier_path()
                .map(default_stego_output_path),
        }
    }


    pub fn apply_partial(&mut self, overlay: PartialLocalConfig) {
        if let Some(v) = overlay.argon_iterations { self.argon_iterations = v; }
        if let Some(v) = overlay.argon_memory { self.argon_memory = v; }
        if let Some(v) = overlay.threshold { self.threshold = v; }
        if let Some(v) = overlay.enabled_factors { self.enabled_factors = v; }
        if let Some(v) = overlay.hash_profile { self.hash_profile = v; }
        if let Some(v) = overlay.rng_mode { self.rng_mode = v; }
        if let Some(v) = overlay.os_rng_required { self.os_rng_required = v; }
        if let Some(v) = overlay.external_entropy_required { self.external_entropy_required = v; }
        if let Some(v) = overlay.external_entropy_mode { self.external_entropy_mode = v; }
        if let Some(v) = overlay.external_entropy_min_bytes { self.external_entropy_min_bytes = v; }
        if overlay.dead_sector_device.is_some() { self.dead_sector_device = overlay.dead_sector_device; }
        if overlay.dead_sector_offset.is_some() { self.dead_sector_offset = overlay.dead_sector_offset; }
        if overlay.dead_sector_display_model.is_some() { self.dead_sector_display_model = overlay.dead_sector_display_model; }
        if overlay.dead_sector_display_partition.is_some() { self.dead_sector_display_partition = overlay.dead_sector_display_partition; }
        if overlay.dead_sector_display_label.is_some() { self.dead_sector_display_label = overlay.dead_sector_display_label; }
        if overlay.stego_carrier_png.is_some() { self.stego_carrier_png = overlay.stego_carrier_png; }
        if overlay.stego_output_png.is_some() { self.stego_output_png = overlay.stego_output_png; }
        if overlay.remote_url.is_some() { self.remote_url = overlay.remote_url; }
        if let Some(v) = overlay.remote_servers { self.remote_servers = v; }
        if let Some(v) = overlay.remote_mode { self.remote_mode = v; }
        if let Some(v) = overlay.remote_quorum_k { self.remote_quorum_k = v; }
        if let Some(v) = overlay.remote_selection_mode { self.remote_selection_mode = v; }
        if let Some(v) = overlay.remote_max_active_servers { self.remote_max_active_servers = v; }
        if let Some(v) = overlay.remote_request_timeout_ms { self.remote_request_timeout_ms = v; }
        if let Some(v) = overlay.remote_retry_backoff_ms { self.remote_retry_backoff_ms = v; }
        if let Some(v) = overlay.remote_require_brain_key_auth { self.remote_require_brain_key_auth = v; }
        if let Some(v) = overlay.remote_auth_mode { self.remote_auth_mode = v; }
        if let Some(v) = overlay.remote_release_mode { self.remote_release_mode = v; }
        if let Some(v) = overlay.remote_require_distinct_servers { self.remote_require_distinct_servers = v; }
        if let Some(v) = overlay.yubikey_mode { self.yubikey_mode = v; }
        if let Some(v) = overlay.yubikey_binary { self.yubikey_binary = v; }
        if let Some(v) = overlay.yubikey_pool_max_active_factors { self.yubikey_pool_max_active_factors = v; }
        if let Some(v) = overlay.yubikey_a_slot { self.yubikey_a_slot = v; }
        if let Some(v) = overlay.yubikey_b_slot { self.yubikey_b_slot = v; }
        if let Some(v) = overlay.yubikey_require_distinct_devices { self.yubikey_require_distinct_devices = v; }
    }
}

pub fn remember_active_config_path(path: Option<&Path>) {
    let resolved = resolve_config_path(path);
    env::set_var(ACTIVE_CONFIG_PATH_ENV, resolved);
}

pub fn remember_ephemeral_dead_sector_locator(locator: &DeadSectorLocator) {
    env::set_var(DEAD_SECTOR_EPHEMERAL_DEVICE_ENV, &locator.canonical_path);
    env::set_var(DEAD_SECTOR_EPHEMERAL_OFFSET_ENV, locator.offset.to_string());
    set_optional_env(DEAD_SECTOR_EPHEMERAL_MODEL_ENV, locator.display_model.as_deref());
    set_optional_env(
        DEAD_SECTOR_EPHEMERAL_PARTITION_ENV,
        locator.display_partition.as_deref(),
    );
    set_optional_env(DEAD_SECTOR_EPHEMERAL_LABEL_ENV, locator.display_label.as_deref());
}

pub fn persist_dead_sector_locator(
    target: DeadSectorPersistTarget,
    locator: &DeadSectorLocator,
    password: Option<&str>,
) -> Result<PathBuf> {
    let config_path = env::var_os(ACTIVE_CONFIG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_config_path(None));

    match target {
        DeadSectorPersistTarget::ConfigYaml => {
            upsert_dead_sector_locator_in_yaml(&config_path, locator)?;
            Ok(config_path)
        }
        DeadSectorPersistTarget::ConfigSealed => {
            let password = password.ok_or_else(|| {
                anyhow!("a password is required to update config.sealed")
            })?;
            let sealed_path = sealed_path_for(Some(config_path.as_path()));
            let mut overlay = if sealed_path.exists() {
                load_sealed_overlay(&sealed_path, password).with_context(|| {
                    format!("failed to decrypt {}", sealed_path.display())
                })?
            } else {
                PartialLocalConfig::default()
            };
            apply_dead_sector_locator_to_partial(&mut overlay, locator);
            seal_partial_config_to_path(&sealed_path, &overlay, password)?;
            Ok(sealed_path)
        }
        DeadSectorPersistTarget::EphemeralRunOnly => {
            remember_ephemeral_dead_sector_locator(locator);
            Ok(config_path)
        }
    }
}

pub fn seal_config_file(
    source_path: &Path,
    output_path: &Path,
    brain_key: &str,
    argon_iterations: Option<u32>,
    argon_memory_kib: Option<u32>,
) -> Result<()> {
    let raw = fs::read_to_string(source_path)
        .with_context(|| format!("could not read {}", source_path.display()))?;
    let partial: PartialLocalConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("could not parse {} as partial local config", source_path.display()))?;
    let canonical = serde_yaml::to_string(&partial)
        .context("failed to serialize partial local config before sealing")?;

    let iterations = argon_iterations.unwrap_or(default_argon_iterations());
    let memory = argon_memory_kib.unwrap_or(default_argon_memory());
    let salt = crate::vault::crypto::generate_salt();
    let nonce = crate::vault::crypto::generate_nonce();
    let key = derive_sealed_config_key(brain_key, &salt, iterations, memory)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for sealed config"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), canonical.as_bytes())
        .map_err(|_| anyhow!("failed to encrypt sealed config"))?;

    let envelope = SealedConfigEnvelope {
        format: SEALED_CONFIG_FORMAT.to_string(),
        kdf: SEALED_CONFIG_KDF.to_string(),
        cipher: SEALED_CONFIG_CIPHER.to_string(),
        argon_iterations: iterations,
        argon_memory_kib: memory,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    };

    let yaml = serde_yaml::to_string(&envelope).context("failed to serialize sealed config envelope")?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
        }
    }
    fs::write(output_path, yaml).with_context(|| format!("could not write {}", output_path.display()))?;
    Ok(())
}

pub fn sealed_exists(path: Option<&Path>) -> bool {
    sealed_path_for(path).exists()
}

pub fn sealed_path_for(path: Option<&Path>) -> PathBuf {
    let path = resolve_config_path(path);
    let dir = path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    dir.join("config.sealed")
}

fn resolve_config_path(path: Option<&Path>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(|| PathBuf::from("config.yaml"))
}

fn normalize_dead_sector_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}


fn default_stego_output_path(path: PathBuf) -> PathBuf {
    let parent = path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let stem = path.file_stem().and_then(|v| v.to_str()).unwrap_or("carrier");
    parent.join(format!("{}.norikey.png", stem))
}

#[cfg(target_os = "linux")]
fn discover_dead_sector_display(path: &Path) -> Option<DeadSectorLocator> {
    discover_dead_sector_display_linux(path)
}

#[cfg(not(target_os = "linux"))]
fn discover_dead_sector_display(_path: &Path) -> Option<DeadSectorLocator> {
    None
}

#[cfg(target_os = "linux")]
fn discover_dead_sector_display_linux(path: &Path) -> Option<DeadSectorLocator> {
    use std::process::Command;

    let path_str = path.to_string_lossy();
    let output = Command::new("lsblk")
        .args([
            "-P",
            "-o",
            "PATH,PKNAME,NAME,MODEL,LABEL,PARTLABEL",
            path_str.as_ref(),
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let mut partition_model = None;
    let mut partition_name = None;
    let mut partition_label = None;
    let mut parent_model = None;

    for line in stdout.lines() {
        let entry = parse_lsblk_pairs(line);
        let entry_path = entry.get("PATH")?;
        if entry_path == path_str.as_ref() {
            partition_model = nonempty(entry.get("MODEL").map(String::as_str));
            partition_name = nonempty(entry.get("PARTLABEL").map(String::as_str))
                .or_else(|| nonempty(entry.get("NAME").map(String::as_str)));
            partition_label = nonempty(entry.get("LABEL").map(String::as_str));

            if let Some(pkname) = nonempty(entry.get("PKNAME").map(String::as_str)) {
                let parent_path = format!("/dev/{pkname}");
                parent_model = stdout
                    .lines()
                    .filter_map(|candidate| {
                        let row = parse_lsblk_pairs(candidate);
                        (row.get("PATH") == Some(&parent_path)).then(|| {
                            nonempty(row.get("MODEL").map(String::as_str))
                        })?
                    })
                    .next()
                    .flatten();
            }
        }
    }

    Some(DeadSectorLocator {
        canonical_path: path.to_path_buf(),
        offset: 0,
        display_model: parent_model.or(partition_model),
        display_partition: partition_name,
        display_label: partition_label,
    })
}

#[cfg(target_os = "linux")]
fn parse_lsblk_pairs(line: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in line.split_whitespace() {
        if let Some((k, v)) = part.split_once('=') {
            let value = v.trim_matches('"').replace("\x20", " ");
            map.insert(k.to_string(), value);
        }
    }
    map
}

#[cfg(target_os = "linux")]
fn nonempty(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|v| !v.is_empty()).map(ToOwned::to_owned)
}

fn ephemeral_dead_sector_locator_from_env() -> Option<DeadSectorLocator> {
    let device = env::var_os(DEAD_SECTOR_EPHEMERAL_DEVICE_ENV)?;
    let offset = env::var(DEAD_SECTOR_EPHEMERAL_OFFSET_ENV).ok()?.parse::<u64>().ok()?;
    Some(DeadSectorLocator {
        canonical_path: normalize_dead_sector_path(Path::new(&device)),
        offset,
        display_model: env::var(DEAD_SECTOR_EPHEMERAL_MODEL_ENV).ok().filter(|v| !v.trim().is_empty()),
        display_partition: env::var(DEAD_SECTOR_EPHEMERAL_PARTITION_ENV).ok().filter(|v| !v.trim().is_empty()),
        display_label: env::var(DEAD_SECTOR_EPHEMERAL_LABEL_ENV).ok().filter(|v| !v.trim().is_empty()),
    })
}

fn set_optional_env(name: &str, value: Option<&str>) {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => env::set_var(name, value),
        None => env::remove_var(name),
    }
}

fn apply_dead_sector_locator_to_partial(overlay: &mut PartialLocalConfig, locator: &DeadSectorLocator) {
    overlay.dead_sector_device = Some(locator.canonical_path.to_string_lossy().to_string());
    overlay.dead_sector_offset = Some(locator.offset);
    overlay.dead_sector_display_model = locator.display_model.clone();
    overlay.dead_sector_display_partition = locator.display_partition.clone();
    overlay.dead_sector_display_label = locator.display_label.clone();
}

fn upsert_dead_sector_locator_in_yaml(path: &Path, locator: &DeadSectorLocator) -> Result<()> {
    let mut root: serde_yaml::Value = if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("could not parse {}", path.display()))?
    } else {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    };

    let mapping = root
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("{} does not contain a YAML mapping at the document root", path.display()))?;

    set_yaml_field(mapping, "dead_sector_device", serde_yaml::Value::String(locator.canonical_path.to_string_lossy().to_string()));
    set_yaml_field(mapping, "dead_sector_offset", serde_yaml::to_value(locator.offset)?);
    set_optional_yaml_field(mapping, "dead_sector_display_model", locator.display_model.as_deref())?;
    set_optional_yaml_field(mapping, "dead_sector_display_partition", locator.display_partition.as_deref())?;
    set_optional_yaml_field(mapping, "dead_sector_display_label", locator.display_label.as_deref())?;

    let yaml = serde_yaml::to_string(&root).context("failed to serialize updated config.yaml")?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
        }
    }
    fs::write(path, yaml).with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

fn set_yaml_field(mapping: &mut serde_yaml::Mapping, key: &str, value: serde_yaml::Value) {
    mapping.insert(serde_yaml::Value::String(key.to_string()), value);
}

fn set_optional_yaml_field(mapping: &mut serde_yaml::Mapping, key: &str, value: Option<&str>) -> Result<()> {
    let key_value = serde_yaml::Value::String(key.to_string());
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => {
            mapping.insert(key_value, serde_yaml::Value::String(v.to_string()));
        }
        None => {
            mapping.remove(&key_value);
        }
    }
    Ok(())
}

fn seal_partial_config_to_path(output_path: &Path, overlay: &PartialLocalConfig, password: &str) -> Result<()> {
    let canonical = serde_yaml::to_string(overlay)
        .context("failed to serialize partial local config before sealing")?;
    let salt = crate::vault::crypto::generate_salt();
    let nonce = crate::vault::crypto::generate_nonce();
    let key = derive_sealed_config_key(password, &salt, default_argon_iterations(), default_argon_memory())?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for sealed config"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), canonical.as_bytes())
        .map_err(|_| anyhow!("failed to encrypt sealed config"))?;

    let envelope = SealedConfigEnvelope {
        format: SEALED_CONFIG_FORMAT.to_string(),
        kdf: SEALED_CONFIG_KDF.to_string(),
        cipher: SEALED_CONFIG_CIPHER.to_string(),
        argon_iterations: default_argon_iterations(),
        argon_memory_kib: default_argon_memory(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    };

    let yaml = serde_yaml::to_string(&envelope).context("failed to serialize sealed config envelope")?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
        }
    }
    fs::write(output_path, yaml).with_context(|| format!("could not write {}", output_path.display()))?;
    Ok(())
}

fn load_sealed_overlay(path: &Path, brain_key: &str) -> Result<PartialLocalConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let envelope: SealedConfigEnvelope = serde_yaml::from_str(&raw)
        .with_context(|| format!("could not parse {}", path.display()))?;

    if envelope.format != SEALED_CONFIG_FORMAT { bail!("unsupported sealed config format '{}'", envelope.format); }
    if envelope.kdf != SEALED_CONFIG_KDF { bail!("unsupported sealed config kdf '{}'", envelope.kdf); }
    if envelope.cipher != SEALED_CONFIG_CIPHER { bail!("unsupported sealed config cipher '{}'", envelope.cipher); }

    let salt = decode_fixed_hex::<16>(&envelope.salt_hex, "sealed config salt")?;
    let nonce = decode_fixed_hex::<12>(&envelope.nonce_hex, "sealed config nonce")?;
    let ciphertext = hex::decode(&envelope.ciphertext_hex).context("sealed config ciphertext is not valid hex")?;
    let key = derive_sealed_config_key(brain_key, &salt, envelope.argon_iterations, envelope.argon_memory_kib)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for sealed config decryption"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt sealed config with the supplied password"))?;

    let partial: PartialLocalConfig = serde_yaml::from_slice(&plaintext)
        .context("decrypted sealed config is not valid YAML")?;
    Ok(partial)
}

fn derive_sealed_config_key(brain_key: &str, salt: &[u8; 16], argon_iterations: u32, argon_memory_kib: u32) -> Result<[u8; 32]> {
    let params = Params::new(argon_memory_kib, argon_iterations, 1, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters for sealed config: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(brain_key.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2id failed while deriving sealed-config key: {e}"))?;
    Ok(out)
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;
    if bytes.len() != N { bail!("{label} must decode to {N} bytes, got {}", bytes.len()); }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

const ACTIVE_CONFIG_PATH_ENV: &str = "NORIKEY_ACTIVE_CONFIG_PATH";
const DEAD_SECTOR_EPHEMERAL_DEVICE_ENV: &str = "NORIKEY_DEAD_SECTOR_DEVICE";
const DEAD_SECTOR_EPHEMERAL_OFFSET_ENV: &str = "NORIKEY_DEAD_SECTOR_OFFSET";
const DEAD_SECTOR_EPHEMERAL_MODEL_ENV: &str = "NORIKEY_DEAD_SECTOR_DISPLAY_MODEL";
const DEAD_SECTOR_EPHEMERAL_PARTITION_ENV: &str = "NORIKEY_DEAD_SECTOR_DISPLAY_PARTITION";
const DEAD_SECTOR_EPHEMERAL_LABEL_ENV: &str = "NORIKEY_DEAD_SECTOR_DISPLAY_LABEL";

const SEALED_CONFIG_FORMAT: &str = "norikey-sealed-config-v1";
const SEALED_CONFIG_KDF: &str = "argon2id";
const SEALED_CONFIG_CIPHER: &str = "aes256-gcm";

const fn default_argon_iterations() -> u32 { 4 }
const fn default_argon_memory() -> u32 { 65_536 }
const fn default_threshold() -> u8 { 3 }
const fn default_hash_profile() -> HashProfile { HashProfile::Blake3 }
const fn default_rng_mode() -> RngMode { RngMode::Standard }
const fn default_yubikey_mode() -> YubiKeyMode { YubiKeyMode::Auto }
fn default_yubikey_binary() -> String { "ykman".to_string() }
const fn default_yubikey_pool_max_active_factors() -> u8 { 2 }
const fn default_yubikey_a_slot() -> u8 { 1 }
const fn default_yubikey_b_slot() -> u8 { 2 }
const fn default_true() -> bool { true }
fn default_external_entropy_mode() -> String { "mix".to_string() }
const fn default_external_entropy_min_bytes() -> u32 { 64 }
const fn default_remote_mode() -> RemoteMode { RemoteMode::Disabled }
const fn default_remote_quorum_k() -> u8 { 1 }
fn default_remote_selection_mode() -> String { "random_subset".to_string() }
const fn default_remote_max_active_servers() -> u8 { 2 }
const fn default_remote_request_timeout_ms() -> u64 { 3500 }
const fn default_remote_retry_backoff_ms() -> u64 { 1200 }
fn default_remote_auth_mode() -> String { "opaque".to_string() }
fn default_remote_release_mode() -> String { "share".to_string() }
const fn default_remote_weight() -> u32 { 100 }

fn default_enabled_factors() -> Vec<FactorKind> {
    vec![
        FactorKind::HardwareId,
        FactorKind::BrainKey,
        FactorKind::Steganography,
        FactorKind::DeadSector,
    ]
}
