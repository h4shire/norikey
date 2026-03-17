use std::process::Command;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroize;

use crate::{
    config::{LocalConfig, YubiKeyMode},
    policy::FactorKind,
    session::{self, YubiKeyLane},
    session_helpers::{
        post_yubikey_interaction_cleanup, read_line_prompt, read_numeric_choice_prompt,
        read_yes_no_prompt,
    },
    vault::{
        header::{ContainerHeader, ShareBinding},
        secret::{CONTAINER_KEY_LEN, NONCE_LEN},
        share::SecretShare,
    },
};

use super::{
    decode_wrapped_share, FactorProvider, PROTECTION_PLAIN, PROTECTION_YUBIKEY_A_DEV_AEAD,
    PROTECTION_YUBIKEY_A_YKMAN_AEAD, PROTECTION_YUBIKEY_B_DEV_AEAD,
    PROTECTION_YUBIKEY_B_YKMAN_AEAD,
};

const YK_A_KEY_CONTEXT: &[u8] = b"norikey/v1/yubikey-a-key";
const YK_A_NONCE_CONTEXT: &[u8] = b"norikey/v1/yubikey-a-nonce";
const YK_A_CHALLENGE_CONTEXT: &[u8] = b"norikey/v1/yubikey-a-challenge";
const YK_A_LOCATOR_DEV: &str = "dev-mock-yubikey-a";

const YK_B_KEY_CONTEXT: &[u8] = b"norikey/v1/yubikey-b-key";
const YK_B_NONCE_CONTEXT: &[u8] = b"norikey/v1/yubikey-b-nonce";
const YK_B_CHALLENGE_CONTEXT: &[u8] = b"norikey/v1/yubikey-b-challenge";
const YK_B_LOCATOR_DEV: &str = "dev-mock-yubikey-b";

const YK_CHALLENGE_LEN: usize = 64;
const ACCESS_CODE_HEX_LEN: usize = 12;

fn factor_lane_label(factor: FactorKind) -> &'static str {
    factor.display_name()
}

fn lane_ui_name(lane: YubiKeyLane) -> &'static str {
    match lane {
        YubiKeyLane::Lane1 => "yubi_key_1",
        YubiKeyLane::Lane2 => "yubi_key_2",
    }
}

fn remaining_lane_labels_after(config: &LocalConfig, current: FactorKind) -> Vec<&'static str> {
    let mut seen_current = false;
    config
        .active_yubikey_factors()
        .into_iter()
        .filter_map(|factor| {
            if factor == current {
                seen_current = true;
                return None;
            }
            if !seen_current {
                return None;
            }
            factor.yubikey_lane_label()
        })
        .collect()
}

#[derive(Clone, Copy)]
struct LaneProfile {
    preferred_slot: u8,
    key_context: &'static [u8],
    nonce_context: &'static [u8],
    challenge_context: &'static [u8],
    dev_locator: &'static str,
    dev_protection: &'static str,
    ykman_protection: &'static str,
}

#[derive(Debug, Clone)]
struct ParsedYubiLocator {
    lane: Option<String>,
    slot: u8,
    serial: Option<String>,
    serial_order: Vec<String>,
    enrolled_devices: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrolledYubiKeyDevice {
    serial: String,
}

impl EnrolledYubiKeyDevice {
    fn new(serial: impl Into<String>) -> Self {
        Self { serial: serial.into() }
    }
}

#[derive(Debug, Clone)]
struct YubiKeyLaneEnrollment {
    slot: u8,
    primary_response: Vec<u8>,
    devices: Vec<EnrolledYubiKeyDevice>,
}

impl YubiKeyLaneEnrollment {
    fn primary_serial(&self) -> Option<&str> {
        self.devices.first().map(|device| device.serial.as_str())
    }

    fn serial_order(&self) -> Vec<String> {
        self.devices.iter().map(|device| device.serial.clone()).collect()
    }

    fn device_count(&self) -> usize {
        self.devices.len()
    }
}

fn format_ykman_locator(factor: FactorKind, enrollment: &YubiKeyLaneEnrollment) -> String {
    let serial_order = enrollment.serial_order();
    let primary_serial = enrollment.primary_serial().unwrap_or("unknown");
    format!(
        "ykman:lane={};slot={};serial={};serial_order={};enrolled_devices={}",
        factor_lane_label(factor),
        enrollment.slot,
        primary_serial,
        serial_order.join(","),
        enrollment.device_count()
    )
}

fn parse_ykman_locator(locator: Option<&str>) -> Option<ParsedYubiLocator> {
    let locator = locator?;
    if let Some(tail) = locator.strip_prefix("ykman:") {
        let mut lane = None;
        let mut slot = None;
        let mut serial = None;
        let mut serial_order = Vec::new();
        let mut enrolled_devices = None;
        for part in tail.split(';') {
            let (key, value) = part.split_once('=')?;
            match key {
                "lane" => {
                    if !value.trim().is_empty() {
                        lane = Some(value.trim().to_string());
                    }
                }
                "slot" => slot = value.parse::<u8>().ok().filter(|v| matches!(v, 1 | 2)),
                "serial" => {
                    if !value.trim().is_empty() {
                        serial = Some(value.trim().to_string());
                    }
                }
                "serial_order" | "serial_pool" => {
                    serial_order = value
                        .split(',')
                        .map(str::trim)
                        .filter(|entry| !entry.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
                "enrolled_devices" | "enrolled_keys" => {
                    enrolled_devices = value.parse::<usize>().ok();
                }
                _ => {}
            }
        }
        if serial_order.is_empty() {
            if let Some(serial_value) = serial.clone() {
                serial_order.push(serial_value);
            }
        }
        if enrolled_devices.is_none() && !serial_order.is_empty() {
            enrolled_devices = Some(serial_order.len());
        }
        return slot.map(|slot| ParsedYubiLocator {
            lane,
            slot,
            serial,
            serial_order,
            enrolled_devices,
        });
    }

    parse_slot_from_locator(Some(locator)).map(|slot| ParsedYubiLocator {
        lane: None,
        slot,
        serial: None,
        serial_order: Vec::new(),
        enrolled_devices: None,
    })
}

fn prioritize_serials(mut detected_serials: Vec<String>, preferred_serials: &[String]) -> Vec<String> {
    let mut prioritized = Vec::with_capacity(detected_serials.len());
    for preferred in preferred_serials {
        if let Some(pos) = detected_serials.iter().position(|candidate| candidate == preferred) {
            prioritized.push(detected_serials.remove(pos));
        }
    }
    prioritized.extend(detected_serials);
    prioritized
}

fn lane_profile_for_factor(factor: FactorKind, config: &LocalConfig) -> Result<LaneProfile> {
    let preferred_slot = config.yubikey_preferred_slot(factor)?;
    match factor {
        FactorKind::YubiKeyA => Ok(LaneProfile {
            preferred_slot,
            key_context: YK_A_KEY_CONTEXT,
            nonce_context: YK_A_NONCE_CONTEXT,
            challenge_context: YK_A_CHALLENGE_CONTEXT,
            dev_locator: YK_A_LOCATOR_DEV,
            dev_protection: PROTECTION_YUBIKEY_A_DEV_AEAD,
            ykman_protection: PROTECTION_YUBIKEY_A_YKMAN_AEAD,
        }),
        FactorKind::YubiKeyB => Ok(LaneProfile {
            preferred_slot,
            key_context: YK_B_KEY_CONTEXT,
            nonce_context: YK_B_NONCE_CONTEXT,
            challenge_context: YK_B_CHALLENGE_CONTEXT,
            dev_locator: YK_B_LOCATOR_DEV,
            dev_protection: PROTECTION_YUBIKEY_B_DEV_AEAD,
            ykman_protection: PROTECTION_YUBIKEY_B_YKMAN_AEAD,
        }),
        _ => bail!("invalid YubiKey factor '{}' for lane profile", factor.as_str()),
    }
}

pub struct YubiKeyLaneProvider {
    factor: FactorKind,
}

pub fn provider_for_yubikey_lane(factor: FactorKind) -> YubiKeyLaneProvider {
    YubiKeyLaneProvider { factor }
}

impl FactorProvider for YubiKeyLaneProvider {
    fn kind(&self) -> FactorKind {
        self.factor
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<ShareBinding> {
        let profile = lane_profile_for_factor(self.kind(), config)?;
        store_share_for_lane(self.kind(), share_id, share, header, config, profile)
    }

    fn collect_share(
        &self,
        binding: &ShareBinding,
        header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<Option<SecretShare>> {
        let profile = lane_profile_for_factor(self.kind(), config)?;
        collect_share_for_lane(self.kind(), binding, header, config, profile)
    }
}

fn store_share_for_lane(
    factor: FactorKind,
    share_id: u8,
    share: &SecretShare,
    header: &ContainerHeader,
    config: &LocalConfig,
    profile: LaneProfile,
) -> Result<ShareBinding> {
    match config.yubikey_mode {
        YubiKeyMode::Dev => store_share_dev(
            factor,
            share_id,
            share,
            header,
            profile.key_context,
            profile.nonce_context,
            profile.dev_locator,
            profile.dev_protection,
        ),
        YubiKeyMode::Ykman => store_share_ykman(
            factor,
            share_id,
            share,
            header,
            config,
            profile.preferred_slot,
            profile.key_context,
            profile.nonce_context,
            profile.challenge_context,
            profile.ykman_protection,
        ),
        YubiKeyMode::Auto => match store_share_ykman(
            factor,
            share_id,
            share,
            header,
            config,
            profile.preferred_slot,
            profile.key_context,
            profile.nonce_context,
            profile.challenge_context,
            profile.ykman_protection,
        ) {
            Ok(binding) => Ok(binding),
            Err(err) => {
                eprintln!(
                    "Warning: failed to use ykman for factor '{}': {}. Falling back to development secret mode.",
                    factor_lane_label(factor),
                    err
                );
                store_share_dev(
                    factor,
                    share_id,
                    share,
                    header,
                    profile.key_context,
                    profile.nonce_context,
                    profile.dev_locator,
                    profile.dev_protection,
                )
            }
        },
    }
}

fn collect_share_for_lane(
    factor: FactorKind,
    binding: &ShareBinding,
    header: &ContainerHeader,
    config: &LocalConfig,
    profile: LaneProfile,
) -> Result<Option<SecretShare>> {
    if binding.factor != factor {
        return Ok(None);
    }

    match binding.protection.as_str() {
        PROTECTION_PLAIN => decode_wrapped_share(binding),
        p if p == profile.dev_protection => {
            collect_share_dev(binding, header, factor, profile.key_context, profile.nonce_context)
        }
        p if p == profile.ykman_protection => collect_share_ykman(
            binding,
            header,
            config,
            factor,
            profile.preferred_slot,
            profile.key_context,
            profile.nonce_context,
            profile.challenge_context,
        ),
        other => bail!(
            "{} provider does not support share protection '{}'",
            factor_lane_label(factor),
            other
        ),
    }
}

fn store_share_dev(
    factor: FactorKind,
    share_id: u8,
    share: &SecretShare,
    header: &ContainerHeader,
    key_context: &[u8],
    nonce_context: &[u8],
    locator: &str,
    protection: &str,
) -> Result<ShareBinding> {
    let mut secret = prompt_dev_secret_for_create(factor)?;
    let wrapping_key = derive_wrapping_key_from_material(secret.as_bytes(), header, key_context)?;
    let binding_nonce = derive_binding_nonce(header, share_id, nonce_context)?;

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for YubiKey share wrapping"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&binding_nonce), share.as_bytes())
        .map_err(|_| anyhow!("failed to encrypt share with YubiKey development secret"))?;

    secret.zeroize();

    Ok(ShareBinding {
        factor,
        share_id,
        locator: Some(locator.to_string()),
        protection: protection.to_string(),
        wrapped_share_hex: Some(hex::encode(ciphertext)),
    })
}

#[allow(clippy::too_many_arguments)]
fn store_share_ykman(
    factor: FactorKind,
    share_id: u8,
    share: &SecretShare,
    header: &ContainerHeader,
    config: &LocalConfig,
    preferred_slot: u8,
    key_context: &[u8],
    nonce_context: &[u8],
    challenge_context: &[u8],
    protection: &str,
) -> Result<ShareBinding> {
    let enrollment = enroll_yubikey_lane(
        factor,
        header,
        config,
        share_id,
        preferred_slot,
        challenge_context,
    )?;

    let wrapping_key = derive_wrapping_key_from_material(
        &enrollment.primary_response,
        header,
        key_context,
    )?;
    let binding_nonce = derive_binding_nonce(header, share_id, nonce_context)?;

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for YubiKey share wrapping"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&binding_nonce), share.as_bytes())
        .map_err(|_| anyhow!("failed to encrypt share with YubiKey challenge-response material"))?;

    if enrollment.device_count() <= 1 {
        eprintln!(
            "Warning: 1 YubiKey device is enrolled for lane '{}'. No additional devices are enrolled for this lane.",
            factor_lane_label(factor)
        );
    }

    Ok(ShareBinding {
        factor,
        share_id,
        locator: Some(format_ykman_locator(
            factor,
            &enrollment,
        )),
        protection: protection.to_string(),
        wrapped_share_hex: Some(hex::encode(ciphertext)),
    })
}

fn collect_share_dev(
    binding: &ShareBinding,
    header: &ContainerHeader,
    factor: FactorKind,
    key_context: &[u8],
    nonce_context: &[u8],
) -> Result<Option<SecretShare>> {
    let ciphertext = match &binding.wrapped_share_hex {
        Some(hex_blob) => hex::decode(hex_blob).with_context(|| {
            format!(
                "{} binding does not contain valid ciphertext hex",
                factor_lane_label(factor)
            )
        })?,
        None => return Ok(None),
    };

    let mut secret = prompt_dev_secret_for_unlock(factor)?;
    let wrapping_key = derive_wrapping_key_from_material(secret.as_bytes(), header, key_context)?;
    let binding_nonce = derive_binding_nonce(header, binding.share_id, nonce_context)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM for YubiKey share unwrap"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&binding_nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt share with provided YubiKey development secret"))?;

    secret.zeroize();
    Ok(Some(SecretShare::from_bytes(plaintext)))
}

#[allow(clippy::too_many_arguments)]
fn collect_share_ykman(
    binding: &ShareBinding,
    header: &ContainerHeader,
    config: &LocalConfig,
    factor: FactorKind,
    preferred_slot: u8,
    key_context: &[u8],
    nonce_context: &[u8],
    challenge_context: &[u8],
) -> Result<Option<SecretShare>> {
    let ciphertext = match &binding.wrapped_share_hex {
        Some(hex_blob) => hex::decode(hex_blob).with_context(|| {
            format!(
                "{} binding does not contain valid ciphertext hex",
                factor_lane_label(factor)
            )
        })?,
        None => return Ok(None),
    };

    let locator_meta = parse_ykman_locator(binding.locator.as_deref());
    let slot = locator_meta
        .as_ref()
        .map(|meta| meta.slot)
        .unwrap_or(preferred_slot.max(1));
    let preferred_serials = locator_meta
        .as_ref()
        .map(|meta| {
            if !meta.serial_order.is_empty() {
                meta.serial_order.clone()
            } else {
                meta.serial.iter().cloned().collect()
            }
        })
        .unwrap_or_default();
    let lane = YubiKeyLane::from_factor(factor)?;
    let serials = prioritize_serials(ykman_list_serials(config)?, &preferred_serials);
    if serials.is_empty() {
        eprintln!(
            "Warning: no YubiKey detected for factor '{}'. Continuing without YubiKey contribution.",
            factor_lane_label(factor)
        );
        return Ok(None);
    }

    if let Some(meta) = locator_meta.as_ref() {
        if let Some(serial) = &meta.serial {
            eprintln!(
                "YubiKey lane '{}' prefers enrolled serial {} on slot {}{}{}.",
                factor_lane_label(factor),
                serial,
                slot,
                meta.enrolled_devices
                    .map(|count| format!(" ({} enrolled device(s) in pool)", count))
                    .unwrap_or_default(),
                meta.lane
                    .as_ref()
                    .map(|lane| format!(" [binding lane={}]", lane))
                    .unwrap_or_default(),
            );
            if meta.serial_order.len() > 1 {
                eprintln!(
                    "YubiKey lane '{}' enrolled device order: {}",
                    factor_lane_label(factor),
                    meta.serial_order.join(", ")
                );
            }
        }
    }

    let challenge = derive_ykman_challenge(header, binding.share_id, slot, challenge_context)?;
    let challenge_hex = hex::encode(challenge);
    let binding_nonce = derive_binding_nonce(header, binding.share_id, nonce_context)?;
    let mut prompted_access_code: Option<String> = None;

    for serial in serials {
        if config.yubikey_require_distinct_devices {
            if let Some(other_lane) = session::yubikey_serial_reserved_by_other_lane(lane, &serial)? {
                eprintln!(
                    "Warning: YubiKey serial {} is reserved by active lane '{}'. Skipping it for lane '{}'.",
                    serial,
                    lane_ui_name(other_lane),
                    lane_ui_name(lane),
                );
                continue;
            }
        }

        eprintln!(
            "Touch your YubiKey to authorize factor '{}' on slot {}...",
            factor_lane_label(factor),
            slot
        );

        let response_material = match ykman_calculate(
            config,
            &serial,
            slot,
            &challenge_hex,
            prompted_access_code.as_deref(),
        ) {
            Ok(value) => value,
            Err(YkmanCalculateError::RestrictedAccess(message)) => {
                let access_code = match prompt_for_access_code(
                    factor,
                    slot,
                    Some(&message),
                )? {
                    Some(code) => code,
                    None => continue,
                };
                prompted_access_code = Some(access_code.clone());
                match ykman_calculate(config, &serial, slot, &challenge_hex, Some(&access_code)) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!(
                            "Warning: failed to use YubiKey serial {} on slot {}: {}",
                            serial,
                            slot,
                            err
                        );
                        continue;
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "Warning: failed to use YubiKey serial {} on slot {}: {}",
                    serial,
                    slot,
                    err
                );
                continue;
            }
        };

        let wrapping_key = match derive_wrapping_key_from_material(&response_material, header, key_context)
        {
            Ok(key) => key,
            Err(err) => {
                eprintln!(
                    "Warning: failed to derive wrapping key from YubiKey serial {}: {}",
                    serial,
                    err
                );
                continue;
            }
        };

        let cipher = match Aes256Gcm::new_from_slice(&wrapping_key) {
            Ok(cipher) => cipher,
            Err(_) => {
                eprintln!(
                    "Warning: failed to initialize AES-256-GCM while using YubiKey serial {}.",
                    serial
                );
                continue;
            }
        };

        match cipher.decrypt(Nonce::from_slice(&binding_nonce), ciphertext.as_ref()) {
            Ok(plaintext) => {
                if config.yubikey_require_distinct_devices {
                    session::reserve_yubikey_serial_for_lane(lane, &serial)?;
                }
                return Ok(Some(SecretShare::from_bytes(plaintext)));
            }
            Err(_) => {
                eprintln!(
                    "Warning: YubiKey serial {} did not match the enrolled secret for factor '{}'.",
                    serial,
                    factor_lane_label(factor)
                );
            }
        }
    }

    eprintln!(
        "Warning: no available YubiKey could satisfy factor '{}'. Continuing without YubiKey contribution.",
        factor_lane_label(factor)
    );
    Ok(None)
}

fn prompt_dev_secret_for_create(factor: FactorKind) -> Result<zeroize::Zeroizing<String>> {
    session::get_or_prompt_yubikey_lane_for_create(YubiKeyLane::from_factor(factor)?)
}

fn prompt_dev_secret_for_unlock(factor: FactorKind) -> Result<zeroize::Zeroizing<String>> {
    session::get_or_prompt_yubikey_lane_for_unlock(YubiKeyLane::from_factor(factor)?)
}

fn derive_wrapping_key_from_material(
    material: &[u8],
    header: &ContainerHeader,
    key_context: &[u8],
) -> Result<[u8; CONTAINER_KEY_LEN]> {
    let salt = header
        .salt_bytes()
        .context("container header has invalid salt for YubiKey derivation")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(key_context);
    hasher.update(&salt);
    hasher.update(material);
    let digest = hasher.finalize();

    let mut out = [0u8; CONTAINER_KEY_LEN];
    out.copy_from_slice(&digest.as_bytes()[..CONTAINER_KEY_LEN]);
    Ok(out)
}

fn derive_binding_nonce(
    header: &ContainerHeader,
    share_id: u8,
    nonce_context: &[u8],
) -> Result<[u8; NONCE_LEN]> {
    let base_nonce = header
        .nonce_bytes()
        .context("container header has invalid nonce for YubiKey binding")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce_context);
    hasher.update(&base_nonce);
    hasher.update(&[share_id]);
    let digest = hasher.finalize();

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    Ok(nonce)
}

fn derive_ykman_challenge(
    header: &ContainerHeader,
    share_id: u8,
    slot: u8,
    challenge_context: &[u8],
) -> Result<[u8; YK_CHALLENGE_LEN]> {
    let salt = header
        .salt_bytes()
        .context("container header has invalid salt for YubiKey challenge derivation")?;
    let nonce = header
        .nonce_bytes()
        .context("container header has invalid nonce for YubiKey challenge derivation")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(challenge_context);
    hasher.update(&salt);
    hasher.update(&nonce);
    hasher.update(&[share_id]);
    hasher.update(&[slot]);
    let mut reader = hasher.finalize_xof();

    let mut out = [0u8; YK_CHALLENGE_LEN];
    reader.fill(&mut out);
    Ok(out)
}

fn enroll_yubikey_lane(
    factor: FactorKind,
    header: &ContainerHeader,
    config: &LocalConfig,
    share_id: u8,
    preferred_slot: u8,
    challenge_context: &[u8],
) -> Result<YubiKeyLaneEnrollment> {
    let challenge = derive_ykman_challenge(header, share_id, preferred_slot.max(1), challenge_context)?;
    // We derive the actual slot-specific challenge again later once the slot is selected.
    let _ = challenge;

    let lane = YubiKeyLane::from_factor(factor)?;
    let primary = enroll_single_yubikey(factor, header, config, share_id, preferred_slot, challenge_context)?;
    let slot = primary.slot;
    let primary_response = primary.response.clone();
    if config.yubikey_require_distinct_devices {
        session::reserve_yubikey_serial_for_lane(lane, &primary.serial)?;
    }
    let mut devices = vec![EnrolledYubiKeyDevice::new(primary.serial.clone())];

    let remaining_lanes = remaining_lane_labels_after(config, factor);
    if config.yubikey_require_distinct_devices && !remaining_lanes.is_empty() {
        eprintln!(
            "This configuration still requires additional distinct YubiKey device(s) for: {}.",
            remaining_lanes.join(", ")
        );
    }

    run_additional_lane_enrollment_loop(
        factor,
        header,
        config,
        share_id,
        slot,
        challenge_context,
        &primary_response,
        &mut devices,
    )?;

    Ok(YubiKeyLaneEnrollment {
        slot,
        primary_response,
        devices,
    })
}

fn run_additional_lane_enrollment_loop(
    factor: FactorKind,
    header: &ContainerHeader,
    config: &LocalConfig,
    share_id: u8,
    slot: u8,
    challenge_context: &[u8],
    expected_response: &[u8],
    devices: &mut Vec<EnrolledYubiKeyDevice>,
) -> Result<()> {
    loop {
        if !prompt_yes_no(
            &format!(
                "Do you want to enroll another YubiKey device for lane '{}' [Y/n]: ",
                factor_lane_label(factor)
            ),
            true,
        )? {
            break;
        }

        eprintln!(
            "Insert the next YubiKey device for lane '{}' and press Enter to continue.",
            factor_lane_label(factor)
        );
        let _ = read_line_prompt("")?;

        match enroll_additional_yubikey_for_lane(
            factor,
            header,
            config,
            share_id,
            slot,
            challenge_context,
            expected_response,
            devices,
        )? {
            Some(device) => devices.push(device),
            None => break,
        }
    }

    Ok(())
}

fn enroll_single_yubikey(
    factor: FactorKind,
    header: &ContainerHeader,
    config: &LocalConfig,
    share_id: u8,
    preferred_slot: u8,
    challenge_context: &[u8],
) -> Result<SelectedYubiKey> {
    let lane = YubiKeyLane::from_factor(factor)?;
    loop {
        let serial = prompt_for_device_selection(config)?;
        if config.yubikey_require_distinct_devices {
            if let Some(other_lane) = session::yubikey_serial_reserved_by_other_lane(lane, &serial)? {
                eprintln!(
                    "Warning: YubiKey serial {} is already reserved for lane '{}'. Choose a different device for lane '{}' or disable yubikey_require_distinct_devices.",
                    serial,
                    lane_ui_name(other_lane),
                    lane_ui_name(lane),
                );
                if !prompt_yes_no("Do you want to try another YubiKey now? [Y/n]: ", true)? {
                    if prompt_yes_no(
                        &format!(
                            "Lane '{}' is still required. Cancel the current run? [y/N]: ",
                            factor_lane_label(factor)
                        ),
                        false,
                    )? {
                        bail!(
                            "no usable YubiKey device was selected for required lane '{}'",
                            factor_lane_label(factor)
                        );
                    }
                    eprintln!(
                        "Keeping the current run open. Insert another YubiKey for lane '{}' and try again.",
                        factor_lane_label(factor)
                    );
                    continue;
                }
                continue;
            }
        }
        let selected = select_slot_for_device(factor, header, config, share_id, preferred_slot, challenge_context, &serial)?;
        if let Some(selected) = selected {
            return Ok(selected);
        }
        if !prompt_yes_no("Do you want to try another YubiKey or slot now? [Y/n]: ", true)? {
            if prompt_yes_no(
                &format!(
                    "Lane '{}' is still required. Cancel the current run? [y/N]: ",
                    factor_lane_label(factor)
                ),
                false,
            )? {
                bail!(
                    "no usable YubiKey slot was selected for required lane '{}'",
                    factor_lane_label(factor)
                );
            }
            eprintln!(
                "Keeping the current run open. Reinsert a suitable YubiKey for lane '{}' and continue.",
                factor_lane_label(factor)
            );
            continue;
        }
    }
}

fn enroll_additional_yubikey_for_lane(
    factor: FactorKind,
    header: &ContainerHeader,
    config: &LocalConfig,
    share_id: u8,
    slot: u8,
    challenge_context: &[u8],
    expected_response: &[u8],
    enrolled_devices: &[EnrolledYubiKeyDevice],
) -> Result<Option<EnrolledYubiKeyDevice>> {
    let lane = YubiKeyLane::from_factor(factor)?;
    let serial = prompt_for_device_selection(config)?;
    if enrolled_devices.iter().any(|known| known.serial == serial) {
        eprintln!(
            "Warning: YubiKey serial {} has already been enrolled for this lane. It does not add device redundancy.",
            serial
        );
        return Ok(None);
    }
    if config.yubikey_require_distinct_devices {
        if let Some(other_lane) = session::yubikey_serial_reserved_by_other_lane(lane, &serial)? {
            eprintln!(
                "Warning: YubiKey serial {} is already reserved for lane '{}'. It cannot also be enrolled for lane '{}'.",
                serial,
                lane_ui_name(other_lane),
                lane_ui_name(lane),
            );
            return Ok(None);
        }
    }

    let challenge = derive_ykman_challenge(header, share_id, slot, challenge_context)?;
    let challenge_hex = hex::encode(challenge);
    let mut access_code = None;

    eprintln!("Touch your YubiKey to verify slot {}...", slot);
    let response = match ykman_calculate(config, &serial, slot, &challenge_hex, None) {
        Ok(value) => value,
        Err(YkmanCalculateError::RestrictedAccess(message)) => {
            access_code = prompt_for_access_code(factor, slot, Some(&message))?;
            match access_code.as_deref() {
                Some(code) => ykman_calculate(config, &serial, slot, &challenge_hex, Some(code))
                    .map_err(|err| anyhow!(err.to_string()))?,
                None => {
                    eprintln!("Warning: protected slot verification was skipped.");
                    return Ok(None);
                }
            }
        }
        Err(err) => {
            eprintln!(
                "Warning: failed to enroll additional YubiKey serial {} on slot {}: {}",
                serial,
                slot,
                err
            );
            return Ok(None);
        }
    };

    if response == expected_response {
        eprintln!(
            "Enrolled additional YubiKey serial {} for lane '{}' using slot {}.",
            serial,
            factor_lane_label(factor),
            slot
        );
        if config.yubikey_require_distinct_devices {
            session::reserve_yubikey_serial_for_lane(lane, &serial)?;
        }
        Ok(Some(EnrolledYubiKeyDevice::new(serial)))
    } else {
        let _ = access_code;
        eprintln!(
            "Warning: YubiKey serial {} does not match the enrolled secret for lane '{}'.",
            serial,
            factor_lane_label(factor)
        );
        Ok(None)
    }
}

fn prompt_for_device_selection(config: &LocalConfig) -> Result<String> {
    loop {
        let serials = ykman_list_serials(config)?;
        if serials.is_empty() {
            let _ = read_line_prompt(
                "No YubiKey detected. Insert a YubiKey and press Enter to scan again: ",
            )?;

            let serials = ykman_list_serials(config)?;
            if serials.is_empty() {
                if !prompt_yes_no("Still no YubiKey detected. Retry device discovery? [Y/n]: ", true)? {
                    bail!("no YubiKey detected via ykman");
                }
                continue;
            }

            if serials.len() == 1 {
                eprintln!("Detected YubiKey serial {}.", serials[0]);
                return Ok(serials[0].clone());
            }

            eprintln!("Detected YubiKeys:");
            for (idx, serial) in serials.iter().enumerate() {
                eprintln!("  {}. {}", idx + 1, serial);
            }
            let allowed: Vec<u8> = (1..=serials.len()).map(|value| value as u8).collect();
            let selection =
                read_numeric_choice_prompt("Select a YubiKey by number: ", &allowed, 1)?;
            return Ok(serials[(selection - 1) as usize].clone());
        }

        if serials.len() == 1 {
            eprintln!("Detected YubiKey serial {}.", serials[0]);
            return Ok(serials[0].clone());
        }

        eprintln!("Detected YubiKeys:");
        for (idx, serial) in serials.iter().enumerate() {
            eprintln!("  {}. {}", idx + 1, serial);
        }
        let allowed: Vec<u8> = (1..=serials.len()).map(|value| value as u8).collect();
        let selection = read_numeric_choice_prompt("Select a YubiKey by number: ", &allowed, 1)?;
        return Ok(serials[(selection - 1) as usize].clone());
    }
}

fn select_slot_for_device(
    factor: FactorKind,
    header: &ContainerHeader,
    config: &LocalConfig,
    share_id: u8,
    preferred_slot: u8,
    challenge_context: &[u8],
    serial: &str,
) -> Result<Option<SelectedYubiKey>> {
    let mut info = ykman_slot_info(config, serial)?;
    let mut access_codes = [None, None];

    loop {
        let probe1 = SlotProbe::from_programming(info[0]);
        let probe2 = SlotProbe::from_programming(info[1]);

        eprintln!("YubiKey serial {} slot status:", serial);
        eprintln!("  Slot 1: {}", probe1.describe());
        eprintln!("  Slot 2: {}", probe2.describe());

        let selected_slot = prompt_slot_selection(preferred_slot, &probe1, &probe2)?;
        let probe = if selected_slot == 1 { &probe1 } else { &probe2 };

        match probe.state {
            SlotProbeState::Candidate => {
                eprintln!("Please touch your YubiKey to authorize slot {}...", selected_slot);
                let challenge = derive_ykman_challenge(header, share_id, selected_slot, challenge_context)?;
                let challenge_hex = hex::encode(challenge);
                match ykman_calculate(
                    config,
                    serial,
                    selected_slot,
                    &challenge_hex,
                    access_codes[(selected_slot - 1) as usize].as_deref(),
                ) {
                    Ok(response) => {
                        return Ok(Some(SelectedYubiKey {
                            serial: serial.to_string(),
                            slot: selected_slot,
                            response,
                        }));
                    }
                    Err(YkmanCalculateError::RestrictedAccess(message)) => {
                        let access_code = prompt_for_access_code(factor, selected_slot, Some(&message))?;
                        match access_code {
                            Some(code) => access_codes[(selected_slot - 1) as usize] = Some(code),
                            None => return Ok(None),
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Error: selected slot {} is not usable for challenge-response.",
                            selected_slot
                        );
                        eprintln!("       {}", err);
                        if !prompt_yes_no("Do you want to select a different slot? [Y/n]: ", true)? {
                            return Ok(None);
                        }
                    }
                }
            }
            SlotProbeState::Free => {
                if !prompt_yes_no(
                    &format!(
                        "Slot {} is free. Do you want to configure it for NoriKey challenge-response with touch? [Y/n]: ",
                        selected_slot
                    ),
                    true,
                )? {
                    return Ok(None);
                }
                provision_slot_for_norikey(config, serial, selected_slot)?;
                info[(selected_slot - 1) as usize] = SlotProgramming::Programmed;
            }
            SlotProbeState::Unusable => {
                eprintln!(
                    "Error: selected slot {} is not usable for NoriKey.",
                    selected_slot
                );
                if let Some(detail) = &probe.detail {
                    eprintln!("       {}", detail);
                }
                if !prompt_yes_no("Do you want to select a different slot? [Y/n]: ", true)? {
                    return Ok(None);
                }
            }
        }
    }
}

fn prompt_slot_selection(preferred_slot: u8, probe1: &SlotProbe, probe2: &SlotProbe) -> Result<u8> {
    let default_slot = if preferred_slot == 2 { 2 } else { 1 };
    loop {
        let slot = read_numeric_choice_prompt(
            &format!(
                "Which slot do you want to use for NoriKey? [1/2] (default: {}): ",
                default_slot
            ),
            &[1, 2],
            default_slot,
        )?;
        let probe = if slot == 1 { probe1 } else { probe2 };
        if matches!(probe.state, SlotProbeState::Candidate | SlotProbeState::Free) {
            return Ok(slot);
        }
        eprintln!("Error: selected slot {} is not usable for NoriKey.", slot);
    }
}

fn prompt_for_access_code(
    factor: FactorKind,
    slot: u8,
    detail: Option<&str>,
) -> Result<Option<String>> {
    if let Some(detail) = detail {
        eprintln!(
            "Warning: slot {} for factor '{}' appears to require an OTP access code ({})",
            slot,
            factor_lane_label(factor),
            detail
        );
    } else {
        eprintln!(
            "Warning: slot {} for factor '{}' appears to require an OTP access code.",
            slot,
            factor_lane_label(factor)
        );
    }

    if !prompt_yes_no("Do you want to enter an OTP access code now? [Y/n]: ", true)? {
        return Ok(None);
    }

    loop {
        let mut code = rpassword::prompt_password("Enter OTP access code (12 hex characters): ")
            .context("failed to read OTP access code")?;
        let normalized = code.trim().to_ascii_lowercase();
        code.zeroize();
        if normalized.is_empty() {
            return Ok(None);
        }
        if normalized.len() != ACCESS_CODE_HEX_LEN || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            eprintln!("Error: OTP access code must contain exactly 12 hexadecimal characters.");
            continue;
        }
        return Ok(Some(normalized));
    }
}

fn provision_slot_for_norikey(config: &LocalConfig, serial: &str, slot: u8) -> Result<()> {
    let output = Command::new(&config.yubikey_binary)
        .args([
            "--device",
            serial,
            "otp",
            "chalresp",
            "--touch",
            "--generate",
            &slot.to_string(),
        ])
        .output()
        .with_context(|| format!("failed to execute '{}' for YubiKey provisioning", config.yubikey_binary))?;

    if let Err(err) = post_yubikey_interaction_cleanup() {
        eprintln!("Warning: failed to clean up terminal input after YubiKey provisioning: {err}");
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "failed to provision YubiKey serial {} slot {} for NoriKey{}",
            serial,
            slot,
            if stderr.is_empty() { String::new() } else { format!(": {stderr}") }
        );
    }

    eprintln!(
        "Provisioned YubiKey serial {} slot {} for NoriKey challenge-response with touch.",
        serial,
        slot
    );
    Ok(())
}

fn ykman_slot_info(config: &LocalConfig, serial: &str) -> Result<[SlotProgramming; 2]> {
    let output = Command::new(&config.yubikey_binary)
        .args(["--device", serial, "otp", "info"])
        .output()
        .with_context(|| format!("failed to execute '{} otp info' for YubiKey serial {}", config.yubikey_binary, serial))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "failed to query YubiKey slot information for serial {}{}",
            serial,
            if stderr.is_empty() { String::new() } else { format!(": {stderr}") }
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    Ok([
        parse_slot_programming(&stdout, 1),
        parse_slot_programming(&stdout, 2),
    ])
}

fn parse_slot_programming(stdout: &str, slot: u8) -> SlotProgramming {
    let needle = format!("slot {}:", slot);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&needle) {
            continue;
        }
        if trimmed.contains("empty") || trimmed.contains("not programmed") {
            return SlotProgramming::Free;
        }
        if trimmed.contains("programmed") {
            return SlotProgramming::Programmed;
        }
    }
    SlotProgramming::Unknown
}

fn parse_slot_from_locator(locator: Option<&str>) -> Option<u8> {
    let locator = locator?;
    let tail = locator.strip_prefix("ykman-slot-")?;
    let slot_digits = tail.split('@').next().unwrap_or(tail);
    slot_digits.parse::<u8>().ok().filter(|slot| matches!(slot, 1 | 2))
}

fn ykman_list_serials(config: &LocalConfig) -> Result<Vec<String>> {
    let output = Command::new(&config.yubikey_binary)
        .args(["list", "--serials"])
        .output()
        .with_context(|| format!("failed to execute '{}'", config.yubikey_binary))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "'{} list --serials' failed with status {}{}",
            config.yubikey_binary,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("WARNING:"))
        .map(|line| line.to_string())
        .collect())
}

fn ykman_calculate(
    config: &LocalConfig,
    serial: &str,
    slot: u8,
    challenge_hex: &str,
    access_code: Option<&str>,
) -> std::result::Result<Vec<u8>, YkmanCalculateError> {
    let mut command = Command::new(&config.yubikey_binary);
    command.arg("--device").arg(serial).arg("otp");
    if let Some(code) = access_code {
        command.arg("--access-code").arg(code);
    }
    command.arg("calculate").arg(slot.to_string()).arg(challenge_hex);

    let output = command
        .output()
        .map_err(|err| YkmanCalculateError::other(format!(
            "failed to execute '{}' for YubiKey serial {}: {}",
            config.yubikey_binary, serial, err
        )))?;

    if let Err(err) = post_yubikey_interaction_cleanup() {
        eprintln!("Warning: failed to clean up terminal input after YubiKey interaction: {err}");
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.to_ascii_lowercase().contains("restricted access") || stderr.to_ascii_lowercase().contains("access code") {
            return Err(YkmanCalculateError::restricted(format!(
                "ykman calculate failed for serial {} slot {}: {}",
                serial, slot, stderr
            )));
        }
        return Err(YkmanCalculateError::other(format!(
            "ykman calculate failed for serial {} slot {}{}",
            serial,
            slot,
            if stderr.is_empty() { String::new() } else { format!(": {stderr}") }
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let response = stdout.trim();
    if response.is_empty() {
        return Err(YkmanCalculateError::other(format!(
            "ykman returned an empty response for serial {} slot {}",
            serial, slot
        )));
    }

    match hex::decode(response) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(response.as_bytes().to_vec()),
    }
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    read_yes_no_prompt(prompt, default_yes)
}

#[derive(Debug, Clone)]
struct SelectedYubiKey {
    serial: String,
    slot: u8,
    response: Vec<u8>,
}


#[derive(Debug, Clone, Copy)]
enum SlotProgramming {
    Programmed,
    Free,
    Unknown,
}

#[derive(Debug, Clone)]
struct SlotProbe {
    state: SlotProbeState,
    detail: Option<String>,
}

impl SlotProbe {
    fn from_programming(programming: SlotProgramming) -> Self {
        match programming {
            SlotProgramming::Programmed => Self {
                state: SlotProbeState::Candidate,
                detail: None,
            },
            SlotProgramming::Free => Self {
                state: SlotProbeState::Free,
                detail: None,
            },
            SlotProgramming::Unknown => Self {
                state: SlotProbeState::Unusable,
                detail: Some("slot status could not be determined".to_string()),
            },
        }
    }

    fn describe(&self) -> String {
        match self.state {
            SlotProbeState::Candidate => "programmed slot (will be verified after selection)".to_string(),
            SlotProbeState::Free => "free slot".to_string(),
            SlotProbeState::Unusable => format!(
                "not usable{}",
                self.detail
                    .as_ref()
                    .map(|value| format!(": {}", value))
                    .unwrap_or_default()
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SlotProbeState {
    Candidate,
    Free,
    Unusable,
}

#[derive(Debug, Clone)]
enum YkmanCalculateError {
    RestrictedAccess(String),
    Other(String),
}

impl YkmanCalculateError {
    fn restricted(message: String) -> Self { Self::RestrictedAccess(message) }
    fn other(message: String) -> Self { Self::Other(message) }
}

impl std::fmt::Display for YkmanCalculateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RestrictedAccess(message) | Self::Other(message) => write!(f, "{}", message),
        }
    }
}
