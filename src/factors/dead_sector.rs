use std::{
    env,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};

use crate::{
    config::{
        self, DeadSectorLocator, DeadSectorPersistTarget, LocalConfig,
    },
    policy::FactorKind,
    session,
    session_helpers::{read_line_prompt, read_numeric_choice_prompt, read_yes_no_prompt},
    vault::{
        header::{ContainerHeader, ShareBinding},
        share::SecretShare,
    },
};

use super::{decode_wrapped_share, FactorProvider, PROTECTION_DEAD_SECTOR_RAW, PROTECTION_PLAIN};

const DEAD_SECTOR_MAGIC: &[u8; 5] = b"NKDS1";
const RAW_WRITE_ENV: &str = "NORIKEY_ALLOW_RAW_WRITES";
const MIN_SAFE_OFFSET: u64 = 16 * 1024 * 1024;
const END_RESERVED_BYTES: u64 = 8 * 1024 * 1024;
const CANDIDATE_SCAN_WINDOW: u64 = 128 * 1024 * 1024;
const CANDIDATE_SCAN_STEP: u64 = 1024 * 1024;
const CANDIDATE_PROBE_BYTES: usize = 4096;

pub struct DeadSectorProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadSectorRiskLevel {
    Safe,
    Warning,
    Danger,
}

#[derive(Debug, Clone)]
struct DeadSectorAssessment {
    locator: DeadSectorLocator,
    risk: DeadSectorRiskLevel,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct PreparedDeadSectorTarget {
    locator: DeadSectorLocator,
    persist_target: Option<DeadSectorPersistTarget>,
    store_locator_in_binding: bool,
}

impl FactorProvider for DeadSectorProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::DeadSector
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        _header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<ShareBinding> {
        let prepared = prepare_dead_sector_write_target(config, share.len())
            .context("failed to prepare dead-sector target")?;

        if is_probable_raw_device(&prepared.locator.canonical_path) && env::var_os(RAW_WRITE_ENV).is_none() {
            eprintln!(
                "Note: writing to raw dead-sector targets is enabled because you confirmed an interactive risk decision. Set {}=1 to skip the safety interlock in unattended expert workflows.",
                RAW_WRITE_ENV
            );
        }

        write_share_record(&prepared.locator.canonical_path, prepared.locator.offset, share).with_context(|| {
            format!(
                "failed to write dead-sector share to {}@{}",
                prepared.locator.canonical_path.display(),
                prepared.locator.offset
            )
        })?;

        if let Some(target) = prepared.persist_target {
            match target {
                DeadSectorPersistTarget::ConfigYaml => {
                    let written = config::persist_dead_sector_locator(target, &prepared.locator, None)
                        .context("failed to persist dead-sector target into config.yaml")?;
                    eprintln!("Stored dead-sector target in {}.", written.display());
                }
                DeadSectorPersistTarget::ConfigSealed => {
                    let password = session::get_or_prompt_brain_key_for_create()
                        .context("password is required to update config.sealed with the selected dead-sector target")?;
                    let written = config::persist_dead_sector_locator(
                        target,
                        &prepared.locator,
                        Some(password.as_str()),
                    )
                    .context("failed to persist dead-sector target into config.sealed")?;
                    eprintln!("Stored dead-sector target in {}.", written.display());
                }
                DeadSectorPersistTarget::EphemeralRunOnly => {
                    config::remember_ephemeral_dead_sector_locator(&prepared.locator);
                    eprintln!(
                        "Dead-sector target will be used only for this run. You will need to provide the location again during recovery."
                    );
                }
            }
        }

        Ok(ShareBinding {
            factor: self.kind(),
            share_id,
            locator: prepared
                .store_locator_in_binding
                .then(|| locator_string(&prepared.locator)),
            protection: PROTECTION_DEAD_SECTOR_RAW.to_string(),
            wrapped_share_hex: None,
        })
    }

    fn collect_share(
        &self,
        binding: &ShareBinding,
        _header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<Option<SecretShare>> {
        if binding.factor != self.kind() {
            return Ok(None);
        }

        match binding.protection.as_str() {
            PROTECTION_PLAIN => decode_wrapped_share(binding),
            PROTECTION_DEAD_SECTOR_RAW => {
                let (path, offset) = binding_dead_sector_target(binding, config)?;
                let share = read_share_record(&path, offset).with_context(|| {
                    format!("failed to read dead-sector share from {}@{}", path.display(), offset)
                })?;
                Ok(Some(share))
            }
            other => bail!(
                "dead sector provider does not support share protection '{}'",
                other
            ),
        }
    }
}

fn locator_string(locator: &DeadSectorLocator) -> String {
    format!("{}@{}", locator.canonical_path.display(), locator.offset)
}

fn prepare_dead_sector_write_target(
    config: &LocalConfig,
    share_len: usize,
) -> Result<PreparedDeadSectorTarget> {
    let locator = config
        .resolved_dead_sector_locator()
        .context("dead sector factor is enabled but no dead sector target is configured")?;

    let assessment = assess_dead_sector_target(&locator, share_len)?;
    match assessment.risk {
        DeadSectorRiskLevel::Safe => Ok(PreparedDeadSectorTarget {
            locator: assessment.locator,
            persist_target: None,
            store_locator_in_binding: true,
        }),
        DeadSectorRiskLevel::Warning => handle_warning_target(assessment),
        DeadSectorRiskLevel::Danger => handle_dangerous_target(assessment, share_len),
    }
}

fn handle_warning_target(assessment: DeadSectorAssessment) -> Result<PreparedDeadSectorTarget> {
    eprintln!("Dead-sector target risk level: WARNING");
    for reason in &assessment.reasons {
        eprintln!("  - {}", reason);
    }
    if !read_yes_no_prompt(
        "Continue with this dead-sector target? [y/N]: ",
        false,
    )? {
        bail!("dead-sector target selection aborted by user");
    }
    Ok(PreparedDeadSectorTarget {
        locator: assessment.locator,
        persist_target: None,
        store_locator_in_binding: true,
    })
}

fn handle_dangerous_target(
    assessment: DeadSectorAssessment,
    share_len: usize,
) -> Result<PreparedDeadSectorTarget> {
    eprintln!("Dead-sector target risk level: DANGER");
    eprintln!(
        "Selected target: {}@{}",
        assessment.locator.canonical_path.display(),
        assessment.locator.offset
    );
    for reason in &assessment.reasons {
        eprintln!("  - {}", reason);
    }
    eprintln!("Writing here may damage data or metadata.");
    eprintln!("How do you want to continue?");
    eprintln!("  1. Pick a low-risk block candidate automatically");
    eprintln!("  2. Use this exact target anyway");
    eprintln!("  3. Abort");

    let choice = read_numeric_choice_prompt("Choose [1/2/3]: ", &[1, 2, 3], 1)?;
    match choice {
        1 => {
            let candidate = find_low_risk_candidate(&assessment.locator, share_len)?
                .ok_or_else(|| anyhow!(
                    "no low-risk dead-sector block candidate could be found automatically"
                ))?;

            eprintln!("A low-risk candidate was found:");
            eprintln!(
                "  target : {}@{}",
                candidate.canonical_path.display(),
                candidate.offset
            );
            if let Some(summary) = candidate.display_summary() {
                eprintln!("  detail : {}", summary);
            }
            eprintln!(
                "  reason : outside the early metadata region and sampled as zero-filled or erased"
            );

            if !read_yes_no_prompt("Use this location? [Y/n]: ", true)? {
                bail!("dead-sector auto-selection cancelled by user");
            }

            let persist_target = choose_dead_sector_persistence()?;
            let store_locator_in_binding = !matches!(persist_target, DeadSectorPersistTarget::EphemeralRunOnly);
            Ok(PreparedDeadSectorTarget {
                locator: candidate,
                persist_target: Some(persist_target),
                store_locator_in_binding,
            })
        }
        2 => {
            let confirmation = read_line_prompt(
                "Type DESTROY to continue with this exact dead-sector target: ",
            )?;
            if confirmation != "DESTROY" {
                bail!("dangerous dead-sector target was not confirmed");
            }
            Ok(PreparedDeadSectorTarget {
                locator: assessment.locator,
                persist_target: None,
                store_locator_in_binding: true,
            })
        }
        _ => bail!("dead-sector target selection aborted by user"),
    }
}

fn choose_dead_sector_persistence() -> Result<DeadSectorPersistTarget> {
    eprintln!("How should the selected dead-sector location be stored?");
    eprintln!("  1. config.sealed (recommended)");
    eprintln!("  2. config.yaml");
    eprintln!("  3. Do not persist, use only for this run");

    let choice = read_numeric_choice_prompt("Choose [1/2/3]: ", &[1, 2, 3], 1)?;
    Ok(match choice {
        1 => DeadSectorPersistTarget::ConfigSealed,
        2 => DeadSectorPersistTarget::ConfigYaml,
        _ => DeadSectorPersistTarget::EphemeralRunOnly,
    })
}

fn assess_dead_sector_target(locator: &DeadSectorLocator, share_len: usize) -> Result<DeadSectorAssessment> {
    let mut reasons = Vec::new();
    let path = &locator.canonical_path;
    let offset = locator.offset;

    if !is_probable_raw_device(path) {
        return Ok(DeadSectorAssessment {
            locator: locator.clone(),
            risk: DeadSectorRiskLevel::Safe,
            reasons: vec!["regular file target".to_string()],
        });
    }

    if is_probable_partition_device(path) {
        reasons.push("selected path appears to be a partition device rather than a whole-disk target".to_string());
    }

    if offset < MIN_SAFE_OFFSET {
        reasons.push(format!(
            "offset {} lies inside the early disk area commonly used by partitioning and boot metadata",
            offset
        ));
    }

    if is_target_mounted(path) {
        reasons.push("selected device currently appears in the mounted-filesystems list".to_string());
    }

    match sample_target_bytes(path, offset, share_len)? {
        SampleClassification::ZeroOrErased => {}
        SampleClassification::ExistingNorikeyRecord => {
            return Ok(DeadSectorAssessment {
                locator: locator.clone(),
                risk: DeadSectorRiskLevel::Safe,
                reasons: vec!["existing NoriKey dead-sector record detected at selected location".to_string()],
            });
        }
        SampleClassification::MixedData => {
            reasons.push("target area already contains non-empty data".to_string());
        }
        SampleClassification::Unavailable => {
            reasons.push("target bytes could not be sampled before writing".to_string());
        }
    }

    let risk = if reasons.iter().any(|reason| {
        reason.contains("partition") || reason.contains("boot metadata") || reason.contains("mounted")
    }) {
        DeadSectorRiskLevel::Danger
    } else {
        DeadSectorRiskLevel::Warning
    };

    Ok(DeadSectorAssessment {
        locator: locator.clone(),
        risk,
        reasons,
    })
}

fn binding_dead_sector_target(binding: &ShareBinding, config: &LocalConfig) -> Result<(PathBuf, u64)> {
    if let Some(locator) = &binding.locator {
        if let Some((path, offset)) = parse_locator(locator) {
            return Ok((path, offset));
        }
    }

    if let Some(fallback) = config.resolved_dead_sector_locator() {
        return Ok((fallback.canonical_path, fallback.offset));
    }

    let prompted = prompt_dead_sector_locator_for_recovery()?;
    Ok((prompted.canonical_path, prompted.offset))
}

fn prompt_dead_sector_locator_for_recovery() -> Result<DeadSectorLocator> {
    eprintln!(
        "Dead-sector location is required for recovery, but no persisted location is configured."
    );
    let path = loop {
        let value = read_line_prompt("Enter the dead-sector device or file path: ")?;
        if !value.trim().is_empty() {
            break PathBuf::from(value.trim());
        }
        eprintln!("Please enter a device or file path.");
    };

    let offset = loop {
        let value = read_line_prompt("Enter the dead-sector byte offset: ")?;
        match value.trim().parse::<u64>() {
            Ok(v) => break v,
            Err(_) => eprintln!("Please enter a valid numeric byte offset."),
        }
    };

    let locator = build_locator(path, offset);
    config::remember_ephemeral_dead_sector_locator(&locator);
    Ok(locator)
}

fn parse_locator(locator: &str) -> Option<(PathBuf, u64)> {
    let idx = locator.rfind('@')?;
    let (path_str, offset_str) = locator.split_at(idx);
    let offset = offset_str.get(1..)?.parse::<u64>().ok()?;
    Some((PathBuf::from(path_str), offset))
}

fn is_probable_raw_device(path: &Path) -> bool {
    let as_str = path.to_string_lossy();
    as_str.starts_with("/dev/") && !as_str.contains("/disk/by-")
}

fn is_probable_partition_device(path: &Path) -> bool {
    let as_str = path.to_string_lossy();
    if let Some(rest) = as_str.strip_prefix("/dev/disk") {
        return rest.contains('s') && rest.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false);
    }
    if let Some(rest) = as_str.strip_prefix("/dev/sd") {
        return rest.chars().skip(1).any(|c| c.is_ascii_digit());
    }
    if let Some(rest) = as_str.strip_prefix("/dev/nvme") {
        return rest.contains('p');
    }
    false
}

fn whole_disk_candidate_path(path: &Path) -> PathBuf {
    let as_str = path.to_string_lossy();
    if let Some(rest) = as_str.strip_prefix("/dev/disk") {
        if let Some(idx) = rest.find('s') {
            if rest[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                return PathBuf::from(format!("/dev/disk{}", &rest[..idx]));
            }
        }
    }
    if let Some(rest) = as_str.strip_prefix("/dev/nvme") {
        if let Some(idx) = rest.rfind('p') {
            if rest[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                return PathBuf::from(format!("/dev/nvme{}", &rest[..idx]));
            }
        }
    }
    if let Some(rest) = as_str.strip_prefix("/dev/sd") {
        let trimmed = rest.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed != rest {
            return PathBuf::from(format!("/dev/sd{}", trimmed));
        }
    }
    path.to_path_buf()
}

fn is_target_mounted(path: &Path) -> bool {
    let output = Command::new("mount").output();
    let Ok(output) = output else { return false; };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let target = path.to_string_lossy();
    stdout.lines().any(|line| line.contains(target.as_ref()))
}

enum SampleClassification {
    ZeroOrErased,
    ExistingNorikeyRecord,
    MixedData,
    Unavailable,
}

fn sample_target_bytes(path: &Path, offset: u64, share_len: usize) -> Result<SampleClassification> {
    let probe_len = (DEAD_SECTOR_MAGIC.len() + 4 + share_len).max(64).min(CANDIDATE_PROBE_BYTES);
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(_) => return Ok(SampleClassification::Unavailable),
    };

    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Ok(SampleClassification::Unavailable);
    }

    let mut buf = vec![0u8; probe_len];
    match file.read(&mut buf) {
        Ok(0) => return Ok(SampleClassification::ZeroOrErased),
        Ok(read) => {
            buf.truncate(read);
        }
        Err(_) => return Ok(SampleClassification::Unavailable),
    }

    if buf.starts_with(DEAD_SECTOR_MAGIC) {
        return Ok(SampleClassification::ExistingNorikeyRecord);
    }

    if buf.iter().all(|b| *b == 0x00) || buf.iter().all(|b| *b == 0xFF) {
        return Ok(SampleClassification::ZeroOrErased);
    }

    Ok(SampleClassification::MixedData)
}

fn find_low_risk_candidate(locator: &DeadSectorLocator, share_len: usize) -> Result<Option<DeadSectorLocator>> {
    let candidate_path = whole_disk_candidate_path(&locator.canonical_path);
    let device_size = target_size_bytes(&candidate_path)?;
    if device_size <= MIN_SAFE_OFFSET + END_RESERVED_BYTES + CANDIDATE_SCAN_STEP {
        return Ok(None);
    }

    let upper = device_size.saturating_sub(END_RESERVED_BYTES);
    let lower = upper.saturating_sub(CANDIDATE_SCAN_WINDOW).max(MIN_SAFE_OFFSET);

    let mut offset = align_down(upper.saturating_sub(CANDIDATE_SCAN_STEP), CANDIDATE_SCAN_STEP);
    while offset >= lower {
        if matches!(
            sample_target_bytes(&candidate_path, offset, share_len)?,
            SampleClassification::ZeroOrErased
        ) {
            return Ok(Some(build_locator(candidate_path.clone(), offset)));
        }
        if offset < CANDIDATE_SCAN_STEP {
            break;
        }
        offset = offset.saturating_sub(CANDIDATE_SCAN_STEP);
    }

    Ok(None)
}

fn build_locator(path: PathBuf, offset: u64) -> DeadSectorLocator {
    DeadSectorLocator {
        canonical_path: canonicalize_best_effort(&path),
        offset,
        display_model: None,
        display_partition: None,
        display_label: None,
    }
}

fn canonicalize_best_effort(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value - (value % alignment)
}

fn target_size_bytes(path: &Path) -> Result<u64> {
    if !is_probable_raw_device(path) {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("could not stat {}", path.display()))?;
        return Ok(meta.len().max(MIN_SAFE_OFFSET + END_RESERVED_BYTES + CANDIDATE_SCAN_WINDOW));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("blockdev")
            .args(["--getsize64", &path.to_string_lossy()])
            .output()
            .with_context(|| format!("failed to query size for {} via blockdev", path.display()))?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(size) = stdout.trim().parse::<u64>() {
                return Ok(size);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("diskutil")
            .args(["info", &path.to_string_lossy()])
            .output()
            .with_context(|| format!("failed to query size for {} via diskutil", path.display()))?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(idx) = line.find("(") {
                    let tail = &line[idx + 1..];
                    if let Some(bytes_idx) = tail.find(" Bytes") {
                        if let Ok(size) = tail[..bytes_idx].trim().parse::<u64>() {
                            return Ok(size);
                        }
                    }
                }
            }
        }
    }

    bail!("could not determine the size of dead-sector target {}", path.display())
}

fn write_share_record(path: &Path, offset: u64, share: &SecretShare) -> Result<()> {
    let mut file = if is_probable_raw_device(path) {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("could not open raw target {}", path.display()))?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("could not open file target {}", path.display()))?
    };

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(DEAD_SECTOR_MAGIC)?;
    file.write_all(&(share.len() as u32).to_be_bytes())?;
    file.write_all(share.as_bytes())?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

fn read_share_record(path: &Path, offset: u64) -> Result<SecretShare> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("could not open dead sector target {}", path.display()))?;

    file.seek(SeekFrom::Start(offset))?;

    let mut magic = [0u8; 5];
    file.read_exact(&mut magic)?;
    if &magic != DEAD_SECTOR_MAGIC {
        bail!(
            "dead sector record at {}@{} does not contain NoriKey dead-sector magic",
            path.display(),
            offset
        );
    }

    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let length = u32::from_be_bytes(len_buf) as usize;

    if length == 0 {
        bail!("dead sector record at {}@{} contains an empty share", path.display(), offset);
    }

    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)?;
    Ok(SecretShare::from_bytes(bytes))
}
