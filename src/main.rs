mod cli;
mod config;
mod factors;
mod panic;
mod policy;
mod session;
mod session_helpers;
mod vault;

use std::{collections::BTreeSet, fs, path::{Path, PathBuf}};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use config::{remember_active_config_path, sealed_exists, sealed_path_for, LocalConfig};
use factors::{build_share_bindings, collect_shares, provider_for};
use policy::{FactorKind, ThresholdPolicy};
use vault::{
    crypto::{decrypt_payload, derive_container_key, derive_container_key_with_remote_gate, encrypt_payload, generate_master_secret},
    header::{read_container, read_header_from_container, write_container, ContainerHeader},
    share::{recover_master_secret, split_master_secret},
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Unlock(args) => run_unlock(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::InitHeader(args) => run_init_header(args),
        Commands::Seal(args) => run_seal(args),
        Commands::SealConfig(args) => run_seal_config(args),
    };

    session::clear_session();
    result
}

fn run_unlock(args: cli::UnlockArgs) -> Result<()> {
    remember_active_config_path(args.config.as_deref());
    let early_brain_key: Option<zeroize::Zeroizing<String>> = if sealed_exists(args.config.as_deref()) {
        Some(session::get_or_prompt_brain_key_for_unlock()?)
    } else {
        None
    };

    let config = LocalConfig::load_with_sealed(
        args.config.as_deref(),
        early_brain_key
            .as_ref()
            .map(|v: &zeroize::Zeroizing<String>| v.as_str()),
    )
    .context("failed to load local configuration")?;
    config
        .validate_yubikey_pool_constraints()
        .context("invalid YubiKey pool constraints in configuration")?;
    config
        .validate_remote_signing_metadata()
        .context("invalid remote signing configuration")?;
    let configured_policy = ThresholdPolicy::from_config(&config)
        .context("invalid threshold policy in configuration")?;
    let effective_policy = effective_local_policy(&config)
        .context("invalid effective local threshold policy in configuration")?;
    let (header, encrypted_payload) = read_container(&args.container)
        .with_context(|| format!("failed to read header from {}", args.container.display()))?;

    header
        .validate()
        .context("container header contains an invalid threshold policy")?;

    println!("NoriKey unlock preflight OK");
    println!("  container : {}", args.container.display());
    println!("  threshold : {}/{}", header.policy.threshold, header.policy.enabled_factors.len());
    println!("  factors   : {}", header.policy.enabled_factors_csv());
    println!("  profile   : {}", header.profile);
    println!("  hash      : {}", header.hash_profile);
    println!("  config    : threshold {}/{}", configured_policy.threshold, configured_policy.enabled_factors.len());
    println!("  yubikey   : {}", config.yubikey_pool_summary());
    print_yubikey_lane_plan(&config);
    println!("  mode      : {:?}", configured_policy.mode());
    if remote_gate_enabled(&config) {
        println!("  local     : threshold {}/{} + mandatory remote gate", effective_policy.threshold, effective_policy.enabled_factors.len());
    }
    print_remote_unlock_plan(&header, &config);
    print_dead_sector_hint(&config);
    print_phase_a_warnings(&configured_policy, &config, header.remote_gate_binding.is_some());
    println!();

    let collected_shares = collect_shares(&header, &config)
        .context("failed to collect shares from configured factors")?;

    if collected_shares.len() < header.policy.threshold as usize {
        bail!(
            "insufficient shares: collected {}, need {}",
            collected_shares.len(),
            header.policy.threshold
        );
    }

    let recovered_secret = recover_master_secret(
        &collected_shares[..header.policy.threshold as usize],
        header.policy.threshold,
    )
    .context("failed to reconstruct master secret from collected shares")?;
    let salt = header.salt_bytes().context("container header has invalid salt")?;
    let (recovered_key, remote_gate_used) = derive_unlock_key(&header, &config, &recovered_secret, &salt)
        .context("failed to derive final container key during unlock")?;
    header
        .verify_integrity(&recovered_key)
        .context("container header integrity verification failed after secret recovery")?;

    println!("NoriKey unlock recovery OK");
    println!("  collected : {} shares", collected_shares.len());
    println!("  threshold : {}", header.policy.threshold);
    println!("  key bytes : {}", recovered_key.as_bytes().len());
    println!("  integrity : {} verified", header.integrity.header_mac_algorithm);
    if remote_gate_used {
        println!("  remote    : mandatory gate released and verified");
    }

    if let Some(payload) = &header.payload {
        let nonce = header
            .payload_nonce_bytes()
            .context("container header has invalid payload nonce")?;
        let aad = if payload.aad_binding {
            header.payload_aad_bytes().context("failed to serialize header for payload AAD")?
        } else {
            Vec::new()
        };
        let plaintext = decrypt_payload(&recovered_key, &nonce, &aad, &encrypted_payload)
            .context("failed to decrypt container payload")?;
        let output_path = args
            .output
            .unwrap_or_else(|| default_unlock_output_path(&args.container));
        fs::write(&output_path, &plaintext)
            .with_context(|| format!("failed to write decrypted payload to {}", output_path.display()))?;
        println!("  payload   : {} bytes decrypted", plaintext.len());
        println!("  output    : {}", output_path.display());
    } else {
        println!();
        println!("No encrypted payload is present in this container.");
    }

    Ok(())
}

fn run_inspect(args: cli::InspectArgs) -> Result<()> {
    let header = read_header_from_container(&args.container)
        .with_context(|| format!("failed to read header from {}", args.container.display()))?;

    println!("Container: {}", args.container.display());
    println!("Format   : {}", header.format);
    println!("Version  : {}", header.version);
    println!("Profile  : {}", header.profile);
    println!("Threshold: {}/{}", header.policy.threshold, header.policy.enabled_factors.len());
    println!("Factors  : {}", header.policy.enabled_factors_csv());
    println!("Hash     : {}", header.hash_profile);
    println!(
        "Argon2   : iterations={}, memory={} KiB",
        header.argon_iterations, header.argon_memory_kib
    );
    println!("Salt     : {}", header.salt_hex);
    println!("Nonce    : {}", header.nonce_hex);
    println!(
        "Integrity: algorithm={}, aad_binding={}, canonicalization={}, mac={}...",
        header.integrity.header_mac_algorithm,
        header.integrity.aad_binding,
        header.integrity.canonicalization,
        &header.integrity.header_mac_hex.chars().take(16).collect::<String>()
    );
    println!(
        "Entropy  : rng_mode={}, os_rng_required={}, external_required={}, external_mode={}, min_bytes={}",
        header.entropy.rng_mode,
        header.entropy.os_rng_required,
        header.entropy.external_entropy_required,
        header.entropy.external_entropy_mode,
        header.entropy.external_entropy_min_bytes
    );
    if let Some(payload) = &header.payload {
        println!(
            "Payload  : cipher={}, aad_binding={}, ciphertext_len={}, nonce={}",
            payload.cipher,
            payload.aad_binding,
            payload.ciphertext_len,
            payload.nonce_hex
        );
    }
    if let Some(binding) = &header.remote_gate_binding {
        println!(
            "RemoteGate: factor={}, share_id={}, protection={}, locator={}",
            binding.factor.as_str(),
            binding.share_id,
            binding.protection,
            binding.locator.as_deref().unwrap_or("<none>")
        );
    }
    if let Some(remote) = &header.remote_quorum {
        println!(
            "Remote   : group_id={}, quorum={}/{}, selection_mode={}, max_active_servers={}, auth_mode={}, release_mode={}",
            remote.group_id,
            remote.quorum_k,
            remote.quorum_n,
            remote.selection_mode,
            remote.max_active_servers,
            remote.auth_mode,
            remote.release_mode
        );
        for server in &remote.server_pool {
            println!(
                "  - server={}, endpoint={}, weight={}",
                server.id, server.endpoint, server.weight
            );
        }
    }
    println!("Bindings : {}", header.share_bindings.len());
    for binding in &header.share_bindings {
        println!(
            "  - factor={}, share_id={}, protection={}, locator={}",
            binding.factor.as_str(),
            binding.share_id,
            binding.protection,
            binding.locator.as_deref().unwrap_or("<none>"),
        );
    }

    Ok(())
}

fn run_init_header(args: cli::InitHeaderArgs) -> Result<()> {
    remember_active_config_path(args.config.as_deref());
    let early_brain_key: Option<zeroize::Zeroizing<String>> = if sealed_exists(args.config.as_deref()) {
        Some(session::get_or_prompt_brain_key_for_create()?)
    } else {
        None
    };

    let config = LocalConfig::load_with_sealed(
        args.config.as_deref(),
        early_brain_key
            .as_ref()
            .map(|v: &zeroize::Zeroizing<String>| v.as_str()),
    )
    .context("failed to load local configuration")?;
    config
        .validate_yubikey_pool_constraints()
        .context("invalid YubiKey pool constraints in configuration")?;
    config
        .validate_remote_signing_metadata()
        .context("invalid remote signing configuration")?;
    let configured_policy = ThresholdPolicy::from_config(&config)
        .context("invalid threshold policy in configuration")?;
    let policy = effective_local_policy(&config)
        .context("invalid effective local threshold policy in configuration")?;
    let mut header = ContainerHeader::from_config(policy.clone(), &config)
        .context("failed to create randomized container header")?;

    let master_secret = generate_master_secret();
    let remote_gate_material = maybe_generate_remote_gate_material(&config);
    let salt = header
        .salt_bytes()
        .context("container header contains an invalid salt right after creation")?;
    let container_key = match remote_gate_material.as_ref() {
        Some(remote_gate_material) => derive_container_key_with_remote_gate(&master_secret, remote_gate_material.as_bytes(), &salt),
        None => derive_container_key(&master_secret, &salt),
    };

    let share_count = policy.enabled_factors.len() as u8;
    let shares = split_master_secret(&master_secret, share_count, policy.threshold)
        .context("failed to split the master secret into shares")?;
    let recovered_secret = recover_master_secret(&shares[..policy.threshold as usize], policy.threshold)
        .context("failed to recover the master secret from the threshold subset")?;
    let recovered_key = match remote_gate_material.as_ref() {
        Some(remote_gate_material) => derive_container_key_with_remote_gate(&recovered_secret, remote_gate_material.as_bytes(), &salt),
        None => derive_container_key(&recovered_secret, &salt),
    };

    if recovered_key.as_bytes() != container_key.as_bytes() {
        bail!("share roundtrip failed: recovered container key does not match the original");
    }

    header.share_bindings = build_share_bindings(
        &policy.enabled_factors,
        &shares,
        &header,
        &config,
    )
    .context("failed to build share bindings for the configured factors")?;
    header.remote_gate_binding = maybe_store_remote_gate_binding(&header, &config, remote_gate_material.as_ref())
        .context("failed to store mandatory remote gate material")?;
    verify_remote_server_roundtrip(&policy, &shares, &header, &config, remote_gate_material.as_ref())
        .context("remote server release verification failed during init-header")?;

    header
        .refresh_integrity(&container_key)
        .context("failed to finalize header integrity binding")?;

    header.validate().context("generated header failed self-validation")?;

    write_container(&args.container, &header, &[])
        .with_context(|| format!("failed to initialize container {}", args.container.display()))?;

    println!("Initialized container header at {}", args.container.display());
    println!("  salt bytes   : {}", salt.len());
    println!("  nonce bytes  : {}", header.nonce_bytes()?.len());
    println!("  key bytes    : {}", container_key.as_bytes().len());
    println!("  shares       : {}", shares.len());
    if header.remote_gate_binding.is_some() {
        println!("  remote gate  : mandatory quorum release");
    }
    println!("  share bytes  : {}", shares.first().map(|s| s.as_bytes().len()).unwrap_or_default());
    println!("  bindings     : {}", header.share_bindings.len());
    println!("  yubikey pool : {}", config.yubikey_pool_summary());
    print_yubikey_lane_plan(&config);
    print_yubikey_lane_reservations(&config);
    println!("  remote mode  : {}", config.remote_mode_summary());
    print_remote_create_plan(&header, &config);
    if let Some(remote) = &header.remote_quorum {
        println!("  remote       : {}/{} over {} server(s)", remote.quorum_k, remote.quorum_n, remote.server_pool.len());
    }
    print_dead_sector_hint(&config);
    print_phase_a_warnings(&configured_policy, &config, header.remote_gate_binding.is_some());
    println!("  integrity    : {}", header.integrity.header_mac_algorithm);
    println!("  roundtrip    : local threshold ok");
    if header.remote_quorum.is_some() {
        println!("  remote check : release path verified");
    }
    println!("  master secret: generated in memory and dropped");
    Ok(())
}

fn run_seal(args: cli::SealArgs) -> Result<()> {
    remember_active_config_path(args.config.as_deref());
    let early_brain_key: Option<zeroize::Zeroizing<String>> = if sealed_exists(args.config.as_deref()) {
        Some(session::get_or_prompt_brain_key_for_create()?)
    } else {
        None
    };

    let config = LocalConfig::load_with_sealed(
        args.config.as_deref(),
        early_brain_key
            .as_ref()
            .map(|v: &zeroize::Zeroizing<String>| v.as_str()),
    )
    .context("failed to load local configuration")?;
    config
        .validate_yubikey_pool_constraints()
        .context("invalid YubiKey pool constraints in configuration")?;
    config
        .validate_remote_signing_metadata()
        .context("invalid remote signing configuration")?;
    let configured_policy = ThresholdPolicy::from_config(&config)
        .context("invalid threshold policy in configuration")?;
    let policy = effective_local_policy(&config)
        .context("invalid effective local threshold policy in configuration")?;
    let payload_plaintext = fs::read(&args.input)
        .with_context(|| format!("failed to read input payload {}", args.input.display()))?;

    let mut header = ContainerHeader::from_config(policy.clone(), &config)
        .context("failed to create randomized container header")?;
    header.prepare_payload_metadata(payload_plaintext.len());

    let master_secret = generate_master_secret();
    let remote_gate_material = maybe_generate_remote_gate_material(&config);
    let salt = header
        .salt_bytes()
        .context("container header contains an invalid salt right after creation")?;
    let container_key = match remote_gate_material.as_ref() {
        Some(remote_gate_material) => derive_container_key_with_remote_gate(&master_secret, remote_gate_material.as_bytes(), &salt),
        None => derive_container_key(&master_secret, &salt),
    };

    let share_count = policy.enabled_factors.len() as u8;
    let shares = split_master_secret(&master_secret, share_count, policy.threshold)
        .context("failed to split the master secret into shares")?;
    let recovered_secret = recover_master_secret(&shares[..policy.threshold as usize], policy.threshold)
        .context("failed to recover the master secret from the threshold subset")?;
    let recovered_key = match remote_gate_material.as_ref() {
        Some(remote_gate_material) => derive_container_key_with_remote_gate(&recovered_secret, remote_gate_material.as_bytes(), &salt),
        None => derive_container_key(&recovered_secret, &salt),
    };
    if recovered_key.as_bytes() != container_key.as_bytes() {
        bail!("share roundtrip failed: recovered container key does not match the original");
    }

    header.share_bindings = build_share_bindings(
        &policy.enabled_factors,
        &shares,
        &header,
        &config,
    )
    .context("failed to build share bindings for the configured factors")?;
    header.remote_gate_binding = maybe_store_remote_gate_binding(&header, &config, remote_gate_material.as_ref())
        .context("failed to store mandatory remote gate material")?;
    verify_remote_server_roundtrip(&policy, &shares, &header, &config, remote_gate_material.as_ref())
        .context("remote server release verification failed during seal")?;

    header
        .refresh_integrity(&container_key)
        .context("failed to finalize header integrity binding")?;
    header.validate().context("generated header failed self-validation")?;

    let payload_nonce = header
        .payload_nonce_bytes()
        .context("container header does not contain valid payload metadata")?;
    let payload_aad = header
        .payload_aad_bytes()
        .context("failed to serialize header for payload AAD")?;
    let encrypted_payload = encrypt_payload(&container_key, &payload_nonce, &payload_aad, &payload_plaintext)
        .context("failed to encrypt container payload")?;

    if let Some(payload) = header.payload.as_mut() {
        payload.ciphertext_len = encrypted_payload.len() as u64;
    }
    header
        .refresh_integrity(&container_key)
        .context("failed to refresh header integrity after payload finalization")?;

    let payload_aad = header
        .payload_aad_bytes()
        .context("failed to serialize finalized header for payload AAD")?;
    let encrypted_payload = encrypt_payload(&container_key, &payload_nonce, &payload_aad, &payload_plaintext)
        .context("failed to encrypt container payload")?;

    write_container(&args.container, &header, &encrypted_payload)
        .with_context(|| format!("failed to write sealed container {}", args.container.display()))?;

    println!("Sealed payload into container {}", args.container.display());
    println!("  input       : {}", args.input.display());
    println!("  plaintext   : {} bytes", payload_plaintext.len());
    println!("  ciphertext  : {} bytes", encrypted_payload.len());
    println!("  threshold   : local {}/{}", policy.threshold, policy.enabled_factors.len());
    println!("  yubikey pool: {}", config.yubikey_pool_summary());
    print_yubikey_lane_plan(&config);
    print_yubikey_lane_reservations(&config);
    println!("  remote mode : {}", config.remote_mode_summary());
    print_remote_create_plan(&header, &config);
    if header.remote_gate_binding.is_some() {
        println!("  remote gate : mandatory quorum release");
    }
    print_dead_sector_hint(&config);
    print_phase_a_warnings(&configured_policy, &config, header.remote_gate_binding.is_some());
    println!("  integrity   : {}", header.integrity.header_mac_algorithm);
    if header.remote_quorum.is_some() {
        println!("  remote check: release path verified");
    }
    Ok(())
}

fn run_seal_config(args: cli::SealConfigArgs) -> Result<()> {
    let config_path = args.config.clone().unwrap_or_else(|| std::path::PathBuf::from("config.yaml"));
    let output_path = args.output.unwrap_or_else(|| sealed_path_for(Some(config_path.as_path())));
    let brain_key = session::get_or_prompt_brain_key_for_seal_config()?;

    config::seal_config_file(
        &args.source,
        &output_path,
        brain_key.as_str(),
        args.iterations,
        args.memory_kib,
    )
    .with_context(|| format!("failed to seal {} into {}", args.source.display(), output_path.display()))?;

    println!("Sealed local config written to {}", output_path.display());
    println!("You can now remove the plaintext sensitive overlay if you no longer need it.");
    Ok(())
}


fn remote_gate_enabled(config: &LocalConfig) -> bool {
    config.remote_gate_enabled()
}

fn effective_local_policy(config: &LocalConfig) -> Result<ThresholdPolicy> {
    let configured = ThresholdPolicy::from_config(config)?;

    if !remote_gate_enabled(config) {
        return Ok(configured);
    }

    if !config.uses_legacy_remote_factor() {
        return Ok(configured);
    }

    let enabled_factors = configured
        .enabled_factors
        .into_iter()
        .filter(|factor| *factor != FactorKind::RemoteShare)
        .collect::<Vec<_>>();

    let threshold = configured.threshold.checked_sub(1).ok_or_else(|| {
        anyhow!("threshold must be at least 2 when legacy remote_share is configured as a mandatory remote gate")
    })?;

    let policy = ThresholdPolicy {
        threshold,
        enabled_factors,
    };
    policy.validate()?;
    Ok(policy)
}

fn maybe_generate_remote_gate_material(config: &LocalConfig) -> Option<vault::share::SecretShare> {
    if !remote_gate_enabled(config) {
        return None;
    }

    let gate = generate_master_secret();
    Some(vault::share::SecretShare::from_bytes(gate.as_bytes().to_vec()))
}

fn maybe_store_remote_gate_binding(
    header: &ContainerHeader,
    config: &LocalConfig,
    remote_gate_material: Option<&vault::share::SecretShare>,
) -> Result<Option<vault::header::ShareBinding>> {
    let Some(remote_gate_material) = remote_gate_material else {
        return Ok(None);
    };

    let provider = provider_for(FactorKind::RemoteShare);
    provider
        .store_share(255, remote_gate_material, header, config)
        .map(Some)
}

fn derive_unlock_key(
    header: &ContainerHeader,
    config: &LocalConfig,
    recovered_secret: &vault::secret::MasterSecret,
    salt: &[u8; vault::secret::SALT_LEN],
) -> Result<(vault::secret::ContainerKey, bool)> {
    if let Some(binding) = &header.remote_gate_binding {
        let provider = provider_for(FactorKind::RemoteShare);
        let remote_gate = provider
            .collect_share(binding, header, config)
            .context("mandatory remote gate release failed during unlock")?
            .ok_or_else(|| anyhow!("mandatory remote gate did not return any material"))?;
        return Ok((
            derive_container_key_with_remote_gate(
                recovered_secret,
                remote_gate.as_bytes(),
                salt,
            ),
            true,
        ));
    }

    Ok((derive_container_key(recovered_secret, salt), false))
}

fn verify_remote_server_roundtrip(
    policy: &ThresholdPolicy,
    shares: &[vault::share::SecretShare],
    header: &ContainerHeader,
    config: &LocalConfig,
    remote_gate_material: Option<&vault::share::SecretShare>,
) -> Result<()> {
    if !remote_gate_enabled(config) && !policy.enabled_factors.contains(&FactorKind::RemoteShare) {
        return Ok(());
    }

    let provider = provider_for(FactorKind::RemoteShare);
    let mut verified_any = false;

    for (idx, binding) in header.share_bindings.iter().enumerate() {
        if binding.factor != FactorKind::RemoteShare {
            continue;
        }

        verified_any = true;
        let expected = shares.get(idx).ok_or_else(|| {
            anyhow!(
                "remote share binding {} does not have a matching generated share",
                binding.share_id
            )
        })?;
        verify_remote_binding_matches(&*provider, binding, expected, header, config).with_context(|| {
            format!(
                "remote threshold binding {} did not roundtrip through release verification",
                binding.share_id
            )
        })?;
    }

    if let Some(binding) = &header.remote_gate_binding {
        verified_any = true;
        let expected = remote_gate_material.ok_or_else(|| {
            anyhow!("remote gate binding exists but no expected remote gate material is available")
        })?;
        verify_remote_binding_matches(&*provider, binding, expected, header, config)
            .context("remote gate binding did not roundtrip through release verification")?;
    }

    if header.remote_quorum.is_some() && !verified_any {
        bail!("remote quorum metadata exists but no remote binding was verified");
    }

    Ok(())
}

fn verify_remote_binding_matches(
    provider: &dyn factors::FactorProvider,
    binding: &vault::header::ShareBinding,
    expected: &vault::share::SecretShare,
    header: &ContainerHeader,
    config: &LocalConfig,
) -> Result<()> {
    let recovered = provider
        .collect_share(binding, header, config)?
        .ok_or_else(|| anyhow!("remote binding {} returned no share data", binding.share_id))?;

    if recovered.as_bytes() != expected.as_bytes() {
        bail!(
            "remote binding {} returned data that does not match the enrolled share",
            binding.share_id
        );
    }

    Ok(())
}

fn print_remote_unlock_plan(header: &ContainerHeader, config: &LocalConfig) {
    let Some(remote) = &header.remote_quorum else {
        return;
    };

    println!(
        "  remote cfg: mode={}, quorum={}, selection={}, max_active={}",
        config.remote_mode_summary(),
        config.remote_quorum_k,
        config.remote_selection_mode,
        config.remote_max_active_servers,
    );
    println!(
        "  remote hdr: {} endpoint(s) embedded in container header",
        remote.server_pool.len()
    );
    let failover_note = if remote.quorum_k == 1 && remote.max_active_servers == 1 && remote.server_pool.len() > 1 {
        ", failover=full-pool"
    } else {
        ""
    };
    println!(
        "  remote sel: mode={}, quorum={}/{}, max_active={}{}",
        remote.selection_mode,
        remote.quorum_k,
        remote.quorum_n,
        remote.max_active_servers,
        failover_note,
    );

    for server in &remote.server_pool {
        println!("  remote srv: {} -> {}", server.id, server.endpoint);
    }

    let configured_servers = config.resolved_remote_servers();
    if !configured_servers.is_empty() {
        let header_set: BTreeSet<(String, String)> = remote
            .server_pool
            .iter()
            .map(|server| (server.id.clone(), server.endpoint.clone()))
            .collect();
        let config_set: BTreeSet<(String, String)> = configured_servers
            .iter()
            .map(|server| (server.id.clone(), server.endpoint.clone()))
            .collect();

        if remote.quorum_k != config.remote_quorum_k
            || remote.selection_mode != config.remote_selection_mode
            || remote.max_active_servers != config.remote_max_active_servers
        {
            println!(
                "  remote note: container header remote policy differs from the currently loaded config"
            );
        }

        if header_set != config_set {
            println!(
                "  remote note: unlock uses header-embedded endpoints; current config differs from the container header"
            );
        }
    }
}

fn print_remote_create_plan(header: &ContainerHeader, config: &LocalConfig) {
    let configured_servers = config.resolved_remote_servers();
    if configured_servers.is_empty() {
        return;
    }

    println!(
        "  remote cfg  : mode={}, quorum={}/{}, selection={}, max_active={}",
        config.remote_mode_summary(),
        config.remote_quorum_k,
        configured_servers.len(),
        config.remote_selection_mode,
        config.remote_max_active_servers,
    );

    if let Some(remote) = &header.remote_quorum {
        println!(
            "  remote hdr  : quorum={}/{}, selection={}, max_active={}",
            remote.quorum_k,
            remote.quorum_n,
            remote.selection_mode,
            remote.max_active_servers,
        );

        if remote.quorum_k != config.remote_quorum_k
            || remote.selection_mode != config.remote_selection_mode
            || remote.max_active_servers != config.remote_max_active_servers
        {
            println!(
                "  remote note : header policy differs from the currently loaded config"
            );
        }
    }
}

fn print_yubikey_lane_plan(config: &LocalConfig) {
    match config.yubikey_lane_plan_summary() {
        Ok(lines) => {
            for line in lines {
                println!("  yubikey lane: {}", line);
            }
        }
        Err(err) => {
            println!("  yubikey lane: unavailable ({})", err);
        }
    }
}

fn print_yubikey_lane_reservations(config: &LocalConfig) {
    for factor in config.active_yubikey_factors() {
        let Ok(lane) = session::YubiKeyLane::from_factor(factor) else {
            continue;
        };
        let Ok(serials) = session::lane_reserved_yubikey_serials(lane) else {
            continue;
        };
        if serials.is_empty() {
            continue;
        }
        let label = factor.yubikey_lane_label().unwrap_or(factor.as_str());
        println!(
            "  yubikey dev : {} reserved device(s): {}",
            label,
            serials.join(", ")
        );
    }
}

fn print_phase_a_warnings(policy: &ThresholdPolicy, config: &LocalConfig, remote_gate_active: bool) {
    if config.uses_legacy_remote_factor() {
        println!(
            "  warning     : legacy remote_share factor semantics are active; migrate to remote_mode: mandatory_gate for the cleaner optional remote model"
        );
    }

    if !remote_gate_active && policy.enabled_factors.contains(&FactorKind::RemoteShare)
        && policy.threshold < policy.enabled_factors.len() as u8
    {
        println!(
            "  warning     : remote_share is enabled but not mandatory under the current pure threshold policy"
        );
    }

    let servers = config.resolved_remote_servers();
    if remote_gate_active && !config.has_remote_servers_configured() {
        println!(
            "  warning     : remote gate is enabled but no remote servers are configured"
        );
    }

    if servers.len() > 1
        && config.remote_quorum_k == 1
        && config.remote_max_active_servers == 1
        && config.remote_selection_mode == "ordered"
    {
        println!(
            "  warning     : ordered remote selection is pinned to a single primary server, so that server is a hard availability dependency"
        );
    }
}


fn print_dead_sector_hint(config: &LocalConfig) {
    if let Some(locator) = config.resolved_dead_sector_locator() {
        let mut line = format!("  dead sector : {}@{}", locator.canonical_path.display(), locator.offset);
        if let Some(summary) = locator.display_summary() {
            line.push_str(&format!(" ({summary})"));
        }
        println!("{line}");
    }
}

fn default_unlock_output_path(container: &Path) -> PathBuf {
    let filename = container
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.out"))
        .unwrap_or_else(|| "payload.out".to_string());
    container.with_file_name(filename)
}
