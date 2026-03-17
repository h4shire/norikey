use std::{collections::{HashMap, HashSet}, sync::{Mutex, OnceLock}};

use anyhow::{bail, Context, Result};

use crate::policy::FactorKind;
use rpassword::prompt_password;
use zeroize::Zeroizing;

const BRAIN_KEY_ENV: &str = "NORIKEY_BRAIN_KEY";
const YK_1_ENV_ALIASES: &[&str] = &[
    "NORIKEY_YUBIKEY_1_SECRET",
    "NORIKEY_YUBIKEY_A_SECRET",
    "NORIKEY_YUBIKEY_PRIMARY_SECRET",
];
const YK_2_ENV_ALIASES: &[&str] = &[
    "NORIKEY_YUBIKEY_2_SECRET",
    "NORIKEY_YUBIKEY_B_SECRET",
    "NORIKEY_YUBIKEY_SECONDARY_SECRET",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum YubiKeyLane {
    Lane1,
    Lane2,
}

impl YubiKeyLane {
    pub(crate) fn from_factor(factor: FactorKind) -> Result<Self> {
        match factor {
            FactorKind::YubiKeyA => Ok(Self::Lane1),
            FactorKind::YubiKeyB => Ok(Self::Lane2),
            _ => bail!("invalid YubiKey factor '{}' for lane mapping", factor.as_str()),
        }
    }

    fn env_aliases(self) -> &'static [&'static str] {
        match self {
            Self::Lane1 => YK_1_ENV_ALIASES,
            Self::Lane2 => YK_2_ENV_ALIASES,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Lane1 => "YubiKey lane 1",
            Self::Lane2 => "YubiKey lane 2",
        }
    }
}

#[derive(Default)]
struct SessionSecrets {
    brain_key: Option<Zeroizing<String>>,
    yubikey_lane_1_secret: Option<Zeroizing<String>>,
    yubikey_lane_2_secret: Option<Zeroizing<String>>,
    yubikey_lane_serials: HashMap<YubiKeyLane, HashSet<String>>,
}

static SESSION: OnceLock<Mutex<SessionSecrets>> = OnceLock::new();

fn session() -> &'static Mutex<SessionSecrets> {
    SESSION.get_or_init(|| Mutex::new(SessionSecrets::default()))
}

pub fn clear_session() {
    if let Ok(mut locked) = session().lock() {
        *locked = SessionSecrets::default();
    }
}

pub fn yubikey_serial_reserved_by_other_lane(
    lane: YubiKeyLane,
    serial: &str,
) -> Result<Option<YubiKeyLane>> {
    let locked = session().lock().map_err(|_| anyhow::anyhow!("session secret cache is poisoned"))?;
    Ok(locked
        .yubikey_lane_serials
        .iter()
        .find_map(|(reserved_lane, serials)| {
            (*reserved_lane != lane && serials.contains(serial)).then_some(*reserved_lane)
        }))
}

pub fn reserve_yubikey_serial_for_lane(lane: YubiKeyLane, serial: &str) -> Result<()> {
    let mut locked = session().lock().map_err(|_| anyhow::anyhow!("session secret cache is poisoned"))?;
    locked
        .yubikey_lane_serials
        .entry(lane)
        .or_default()
        .insert(serial.to_string());
    Ok(())
}

pub fn lane_reserved_yubikey_serials(lane: YubiKeyLane) -> Result<Vec<String>> {
    let locked = session().lock().map_err(|_| anyhow::anyhow!("session secret cache is poisoned"))?;
    Ok(locked
        .yubikey_lane_serials
        .get(&lane)
        .map(|serials| serials.iter().cloned().collect())
        .unwrap_or_default())
}

pub fn get_or_prompt_brain_key_for_create() -> Result<Zeroizing<String>> {
    if let Some(cached) = get_cached_brain_key() { return Ok(cached); }
    if let Some(from_env) = read_secret_from_env(BRAIN_KEY_ENV) {
        store_brain_key(&from_env)?;
        return Ok(Zeroizing::new(from_env));
    }
    let first = prompt_password("Enter NoriKey password for share protection: ").context("failed to read password from terminal")?;
    if first.is_empty() { bail!("password must not be empty"); }
    let second = prompt_password("Confirm NoriKey password: ").context("failed to read password confirmation from terminal")?;
    if first != second { bail!("password confirmation does not match"); }
    store_brain_key(&first)?;
    Ok(Zeroizing::new(first))
}

pub fn get_or_prompt_brain_key_for_unlock() -> Result<Zeroizing<String>> {
    if let Some(cached) = get_cached_brain_key() { return Ok(cached); }
    if let Some(from_env) = read_secret_from_env(BRAIN_KEY_ENV) {
        store_brain_key(&from_env)?;
        return Ok(Zeroizing::new(from_env));
    }
    let value = prompt_password("Enter NoriKey password: ").context("failed to read password from terminal")?;
    if value.is_empty() { bail!("password must not be empty"); }
    store_brain_key(&value)?;
    Ok(Zeroizing::new(value))
}

pub fn get_or_prompt_brain_key_for_seal_config() -> Result<Zeroizing<String>> {
    if let Some(cached) = get_cached_brain_key() { return Ok(cached); }
    if let Some(from_env) = read_secret_from_env(BRAIN_KEY_ENV) {
        store_brain_key(&from_env)?;
        return Ok(Zeroizing::new(from_env));
    }
    let first = prompt_password("Enter NoriKey password for config sealing: ").context("failed to read password for config sealing")?;
    if first.is_empty() { bail!("password must not be empty"); }
    let second = prompt_password("Confirm NoriKey password for config sealing: ").context("failed to read password confirmation for config sealing")?;
    if first != second { bail!("password confirmation does not match"); }
    store_brain_key(&first)?;
    Ok(Zeroizing::new(first))
}

pub fn get_or_prompt_yubikey_lane_for_create(lane: YubiKeyLane) -> Result<Zeroizing<String>> {
    get_or_prompt_yubikey_secret_for_create(
        lane,
        &format!("Enter NoriKey {} development secret: ", lane.label()),
        &format!("Confirm NoriKey {} development secret: ", lane.label()),
        &format!("{} development secret", lane.label()),
    )
}

pub fn get_or_prompt_yubikey_lane_for_unlock(lane: YubiKeyLane) -> Result<Zeroizing<String>> {
    get_or_prompt_yubikey_secret_for_unlock(
        lane,
        &format!("Enter NoriKey {} development secret: ", lane.label()),
        &format!("{} development secret", lane.label()),
    )
}

fn get_or_prompt_yubikey_secret_for_create(
    lane: YubiKeyLane,
    first_prompt: &str,
    confirm_prompt: &str,
    label: &str,
) -> Result<Zeroizing<String>> {
    if let Some(cached) = get_cached_lane(lane) { return Ok(cached); }
    if let Some(from_env) = read_secret_from_env_aliases(lane.env_aliases()) {
        store_lane(lane, &from_env)?;
        return Ok(Zeroizing::new(from_env));
    }
    let first = prompt_password(first_prompt).with_context(|| format!("failed to read {label} from terminal"))?;
    if first.is_empty() { bail!("{label} must not be empty"); }
    let second = prompt_password(confirm_prompt).with_context(|| format!("failed to read {label} confirmation"))?;
    if first != second { bail!("{label} confirmation does not match"); }
    store_lane(lane, &first)?;
    Ok(Zeroizing::new(first))
}

fn get_or_prompt_yubikey_secret_for_unlock(
    lane: YubiKeyLane,
    prompt: &str,
    label: &str,
) -> Result<Zeroizing<String>> {
    if let Some(cached) = get_cached_lane(lane) { return Ok(cached); }
    if let Some(from_env) = read_secret_from_env_aliases(lane.env_aliases()) {
        store_lane(lane, &from_env)?;
        return Ok(Zeroizing::new(from_env));
    }
    let value = prompt_password(prompt).with_context(|| format!("failed to read {label} from terminal"))?;
    if value.is_empty() { bail!("{label} must not be empty"); }
    store_lane(lane, &value)?;
    Ok(Zeroizing::new(value))
}

fn read_secret_from_env(env_name: &str) -> Option<String> {
    std::env::var(env_name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn read_secret_from_env_aliases(env_names: &[&str]) -> Option<String> {
    env_names.iter().find_map(|name| read_secret_from_env(name))
}

fn get_cached_brain_key() -> Option<Zeroizing<String>> {
    let locked = session().lock().ok()?;
    locked.brain_key.as_ref().map(|value| Zeroizing::new(value.as_str().to_owned()))
}

fn store_brain_key(value: &str) -> Result<()> {
    let mut locked = session().lock().map_err(|_| anyhow::anyhow!("session secret cache is poisoned"))?;
    locked.brain_key = Some(Zeroizing::new(value.to_owned()));
    Ok(())
}

fn get_cached_lane(lane: YubiKeyLane) -> Option<Zeroizing<String>> {
    let locked = session().lock().ok()?;
    match lane {
        YubiKeyLane::Lane1 => locked.yubikey_lane_1_secret.as_ref().map(|v| Zeroizing::new(v.as_str().to_owned())),
        YubiKeyLane::Lane2 => locked.yubikey_lane_2_secret.as_ref().map(|v| Zeroizing::new(v.as_str().to_owned())),
    }
}

fn store_lane(lane: YubiKeyLane, value: &str) -> Result<()> {
    let mut locked = session().lock().map_err(|_| anyhow::anyhow!("session secret cache is poisoned"))?;
    match lane {
        YubiKeyLane::Lane1 => locked.yubikey_lane_1_secret = Some(Zeroizing::new(value.to_owned())),
        YubiKeyLane::Lane2 => locked.yubikey_lane_2_secret = Some(Zeroizing::new(value.to_owned())),
    }
    Ok(())
}
