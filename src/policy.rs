use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::LocalConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactorKind {
    #[serde(rename = "hardware_id")]
    HardwareId,
    #[serde(rename = "brain_key")]
    BrainKey,
    #[serde(
        rename = "yubi_key_a",
        alias = "yubikey_a",
        alias = "yubi_key_1",
        alias = "yubikey_1",
        alias = "yubi_key_primary"
    )]
    YubiKeyA,
    #[serde(
        rename = "yubi_key_b",
        alias = "yubikey_b",
        alias = "yubi_key_2",
        alias = "yubikey_2",
        alias = "yubi_key_secondary"
    )]
    YubiKeyB,
    #[serde(rename = "steganography")]
    Steganography,
    #[serde(rename = "dead_sector")]
    DeadSector,
    #[serde(rename = "remote_share", alias = "remote_hash")]
    RemoteShare,
}

impl FactorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardwareId => "hardware_id",
            Self::BrainKey => "brain_key",
            Self::YubiKeyA => "yubi_key_a",
            Self::YubiKeyB => "yubi_key_b",
            Self::Steganography => "steganography",
            Self::DeadSector => "dead_sector",
            Self::RemoteShare => "remote_share",
        }
    }


    pub fn is_yubikey_factor(self) -> bool {
        matches!(self, Self::YubiKeyA | Self::YubiKeyB)
    }

    pub fn yubikey_lane_label(self) -> Option<&'static str> {
        match self {
            Self::YubiKeyA => Some("yubi_key_1"),
            Self::YubiKeyB => Some("yubi_key_2"),
            _ => None,
        }
    }


    pub fn display_name(self) -> &'static str {
        self.yubikey_lane_label().unwrap_or(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    ThreeOfFive,
    FourOfSix,
    FourOfSeven,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPolicy {
    pub threshold: u8,
    pub enabled_factors: Vec<FactorKind>,
}

impl ThresholdPolicy {
    pub fn from_config(config: &LocalConfig) -> Result<Self> {
        let policy = Self {
            threshold: config.threshold,
            enabled_factors: config.enabled_factors.clone(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.enabled_factors.is_empty() {
            bail!("at least one factor must be enabled");
        }

        if self.threshold == 0 {
            bail!("threshold must be greater than zero");
        }

        if self.threshold as usize > self.enabled_factors.len() {
            bail!(
                "threshold {} exceeds enabled factor count {}",
                self.threshold,
                self.enabled_factors.len()
            );
        }

        let mut seen = std::collections::HashSet::new();
        for factor in &self.enabled_factors {
            if !seen.insert(*factor) {
                bail!("factor '{}' is configured more than once", factor.as_str());
            }
        }

        Ok(())
    }

    pub fn mode(&self) -> PolicyMode {
        match (self.threshold, self.enabled_factors.len()) {
            (3, 5) => PolicyMode::ThreeOfFive,
            (4, 6) => PolicyMode::FourOfSix,
            (4, 7) => PolicyMode::FourOfSeven,
            _ => PolicyMode::Custom,
        }
    }

    pub fn enabled_factors_csv(&self) -> String {
        self.enabled_factors
            .iter()
            .map(|factor| factor.display_name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
