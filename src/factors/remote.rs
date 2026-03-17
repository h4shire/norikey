use std::{convert::TryFrom, thread, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::getrandom;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::{
    config::LocalConfig,
    policy::FactorKind,
    session,
    vault::{
        header::{ContainerHeader, RemoteQuorumPolicy, RemoteServerEntry, ShareBinding},
        share::SecretShare,
    },
};

use super::{
    decode_wrapped_share, FactorProvider, PROTECTION_PLAIN, PROTECTION_REMOTE_QUORUM_RELEASE,
};

const REMOTE_AUTH_CONTEXT: &[u8] = b"norikey/v1/remote-auth";
const ACTION_ENROLL: &str = "enroll";
const ACTION_RELEASE: &str = "release";

pub struct RemoteShareProvider;

impl FactorProvider for RemoteShareProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::RemoteShare
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        header: &ContainerHeader,
        _config: &LocalConfig,
    ) -> Result<ShareBinding> {
        if let Some(quorum) = &header.remote_quorum {
            enroll_remote_quorum(binding_container_id(header)?, share_id, share, quorum, header)?;
            return Ok(ShareBinding {
                factor: self.kind(),
                share_id,
                locator: Some(format!("remote-quorum:{}", quorum.group_id)),
                protection: PROTECTION_REMOTE_QUORUM_RELEASE.to_string(),
                wrapped_share_hex: None,
            });
        }

        bail!("remote_share is enabled but remote_quorum metadata is missing")
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
            PROTECTION_REMOTE_QUORUM_RELEASE => {
                let quorum = header.remote_quorum.as_ref().ok_or_else(|| {
                    anyhow!("remote_share binding exists but remote_quorum metadata is missing")
                })?;
                let container_id = binding_container_id(header)?;
                let share = release_remote_quorum(container_id, binding.share_id, quorum, header)?;
                Ok(Some(share))
            }
            other => bail!(
                "remote-share provider does not support share protection '{}'",
                other
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct RemoteServerAttempt {
    server_id: String,
    endpoint: String,
    accepted: bool,
    detail: String,
}

#[derive(Debug, Clone)]
struct RemoteQuorumDebug {
    attempts: Vec<RemoteServerAttempt>,
    accepted_count: usize,
    required_count: usize,
}

impl RemoteQuorumDebug {
    fn new(required_count: usize) -> Self {
        Self {
            attempts: Vec::new(),
            accepted_count: 0,
            required_count,
        }
    }

    fn push_accepted(&mut self, server: &RemoteServerEntry, detail: impl Into<String>) {
        self.accepted_count += 1;
        self.attempts.push(RemoteServerAttempt {
            server_id: server.id.clone(),
            endpoint: server.endpoint.clone(),
            accepted: true,
            detail: detail.into(),
        });
    }

    fn push_rejected(&mut self, server: &RemoteServerEntry, detail: impl Into<String>) {
        self.attempts.push(RemoteServerAttempt {
            server_id: server.id.clone(),
            endpoint: server.endpoint.clone(),
            accepted: false,
            detail: detail.into(),
        });
    }

    fn accepted_ids(&self) -> String {
        let ids = self
            .attempts
            .iter()
            .filter(|attempt| attempt.accepted)
            .map(|attempt| attempt.server_id.clone())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            "<none>".to_string()
        } else {
            ids.join(", ")
        }
    }

    fn rejected_details(&self) -> String {
        let rejected = self
            .attempts
            .iter()
            .filter(|attempt| !attempt.accepted)
            .map(|attempt| format!("{} ({}): {}", attempt.server_id, attempt.endpoint, attempt.detail))
            .collect::<Vec<_>>();
        if rejected.is_empty() {
            "<none>".to_string()
        } else {
            rejected.join("; ")
        }
    }

    fn format_quorum_failure(&self, prefix: &str) -> String {
        format!(
            "{} (accepted: [{}], rejected: [{}], collected {}, required {})",
            prefix,
            self.accepted_ids(),
            self.rejected_details(),
            self.accepted_count,
            self.required_count
        )
    }
}

fn enroll_remote_quorum(
    container_id: String,
    share_id: u8,
    share: &SecretShare,
    quorum: &RemoteQuorumPolicy,
    header: &ContainerHeader,
) -> Result<()> {
    if quorum.server_pool.is_empty() {
        bail!("remote quorum server pool is empty");
    }

    let password = session::get_or_prompt_brain_key_for_unlock()?;
    let auth_token = derive_remote_auth_token(password.as_str(), header, quorum)
        .context("failed to derive remote-share authorization token from password")?;
    let auth_verifier = derive_remote_auth_verifier(&auth_token);
    let client = build_http_client(quorum.request_timeout_ms)?;

    let subshares = split_remote_factor_share(share, quorum.quorum_n, quorum.quorum_k)
        .context("failed to split remote factor share across quorum servers")?;

    for (server, server_share) in quorum.server_pool.iter().zip(subshares.iter()) {
        let request = EnrollRequest {
            action: ACTION_ENROLL.to_string(),
            container_id: container_id.clone(),
            group_id: quorum.group_id.clone(),
            share_id,
            auth_verifier_hex: hex::encode(auth_verifier),
            server_share_hex: hex::encode(server_share.as_bytes()),
        };

        send_enroll(&client, server, &request).with_context(|| {
            format!(
                "failed to enroll remote subshare on server '{}'",
                server.id
            )
        })?;
    }

    Ok(())
}

fn release_remote_quorum(
    container_id: String,
    share_id: u8,
    quorum: &RemoteQuorumPolicy,
    header: &ContainerHeader,
) -> Result<SecretShare> {
    let password = session::get_or_prompt_brain_key_for_unlock()?;
    let auth_token = derive_remote_auth_token(password.as_str(), header, quorum)
        .context("failed to derive remote-share authorization token from password")?;
    let client = build_http_client(quorum.request_timeout_ms)?;
    let selected_servers = select_remote_servers(quorum)?;

    let mut recovered_subshares = Vec::new();
    let mut debug = RemoteQuorumDebug::new(quorum.quorum_k as usize);

    for (idx, server) in selected_servers.iter().enumerate() {
        let request_nonce_hex = random_hex(16).context("failed to generate remote request nonce")?;

        let request = ReleaseRequest {
            action: ACTION_RELEASE.to_string(),
            container_id: container_id.clone(),
            group_id: quorum.group_id.clone(),
            share_id,
            auth_token_hex: hex::encode(auth_token),
            request_nonce_hex: request_nonce_hex.clone(),
        };

        match send_release(&client, server, &request) {
            Ok(server_share) => {
                debug.push_accepted(server, "valid remote subshare accepted");
                recovered_subshares.push(server_share);
                if recovered_subshares.len() >= quorum.quorum_k as usize {
                    break;
                }
            }
            Err(err) => {
                debug.push_rejected(server, format!("{:#}", err));
            }
        }

        if idx + 1 < selected_servers.len() && quorum.retry_backoff_ms > 0 {
            thread::sleep(Duration::from_millis(quorum.retry_backoff_ms));
        }
    }

    if recovered_subshares.len() < quorum.quorum_k as usize {
        bail!(
            "{}",
            debug.format_quorum_failure(&format!(
                "remote quorum not satisfied"
            ))
        );
    }

    recover_remote_factor_share(&recovered_subshares, quorum.quorum_k).map_err(|err| {
        anyhow!(
            "{}",
            debug.format_quorum_failure(&format!(
                "failed to reconstruct remote factor share from quorum responses: {:#}",
                err
            ))
        )
    })
}

fn select_remote_servers(quorum: &RemoteQuorumPolicy) -> Result<Vec<RemoteServerEntry>> {
    let mut servers = quorum.server_pool.clone();

    match quorum.selection_mode.as_str() {
        "ordered" => {}
        "random_subset" | "weighted_random" => shuffle_servers(&mut servers)?,
        other => bail!("unsupported remote selection_mode '{}'", other),
    }

    let take = if quorum.quorum_k == 1 && quorum.max_active_servers == 1 && servers.len() > 1 {
        servers.len()
    } else {
        usize::from(
            quorum
                .max_active_servers
                .max(quorum.quorum_k)
                .min(quorum.quorum_n),
        )
    };

    servers.truncate(take.min(servers.len()));
    Ok(servers)
}

fn shuffle_servers(servers: &mut [RemoteServerEntry]) -> Result<()> {
    if servers.len() <= 1 {
        return Ok(());
    }

    let mut random = vec![0u8; servers.len() * 8];
    getrandom(&mut random).context("failed to obtain randomness for remote server selection")?;

    for idx in (1..servers.len()).rev() {
        let start = idx * 8;
        let chunk = &random[start - 8..start];
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let rnd = u64::from_le_bytes(bytes);
        let swap_idx = (rnd as usize) % (idx + 1);
        servers.swap(idx, swap_idx);
    }

    Ok(())
}

fn send_enroll(client: &Client, server: &RemoteServerEntry, request: &EnrollRequest) -> Result<()> {
    let response = client
        .post(&server.endpoint)
        .json(request)
        .send()
        .with_context(|| format!("failed to contact remote share server {}", server.endpoint))?;

    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| "<unreadable response body>".to_string());

    if !status.is_success() {
        bail!(
            "remote share enrollment returned HTTP {}: {}",
            status,
            body
        );
    }

    let parsed: GenericResponse = serde_json::from_str(&body)
        .context("failed to parse enrollment response from remote share server")?;

    if !parsed.ok {
        let message = parsed
            .error
            .unwrap_or_else(|| "remote share enrollment was rejected by server".to_string());
        bail!("{message}");
    }

    Ok(())
}

fn send_release(
    client: &Client,
    server: &RemoteServerEntry,
    request: &ReleaseRequest,
) -> Result<SecretShare> {
    let response = client
        .post(&server.endpoint)
        .json(request)
        .send()
        .with_context(|| format!("failed to contact remote share server {}", server.endpoint))?;

    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| "<unreadable response body>".to_string());

    if !status.is_success() {
        bail!(
            "remote share release returned HTTP {}: {}",
            status,
            body
        );
    }

    let parsed: ReleaseResponse =
        serde_json::from_str(&body).context("failed to parse remote share release response")?;

    if !parsed.ok {
        let message = parsed
            .error
            .unwrap_or_else(|| "remote share release was rejected by server".to_string());
        bail!("{message}");
    }

    let server_share_hex = parsed
        .server_share_hex
        .clone()
        .ok_or_else(|| anyhow!("remote share server did not return a subshare payload"))?;

    let response_nonce = parsed
        .request_nonce_hex
        .clone()
        .ok_or_else(|| anyhow!("remote share response is missing request_nonce_hex"))?;

    if response_nonce.to_lowercase() != request.request_nonce_hex.to_lowercase() {
        bail!("remote share response nonce does not match the request nonce");
    }

    let response_key_id = parsed
        .response_sig_key_id
        .clone()
        .ok_or_else(|| anyhow!("remote share response is missing response_sig_key_id"))?;

    let response_sig_hex = parsed
        .response_sig_hex
        .clone()
        .ok_or_else(|| anyhow!("remote share response is missing response_sig_hex"))?;

    let expected_key_id = server
        .response_sig_key_id
        .clone()
        .ok_or_else(|| anyhow!("remote share server key id is missing from the container header"))?;

    if response_key_id != expected_key_id {
        bail!(
            "remote share response key id '{}' does not match expected key id '{}'",
            response_key_id,
            expected_key_id
        );
    }

    let pubkey_hex = server
        .response_sig_pubkey_hex
        .clone()
        .ok_or_else(|| anyhow!("remote share server public key is missing from the container header"))?;

    verify_release_signature(
        &pubkey_hex,
        &parsed.container_id,
        &parsed.group_id,
        parsed.share_id,
        &response_nonce,
        &server_share_hex,
        &response_sig_hex,
    )?;

    let bytes = hex::decode(&server_share_hex).with_context(|| {
        format!(
            "remote share server returned invalid share hex for {}",
            server.endpoint
        )
    })?;

    Ok(SecretShare::from_bytes(bytes))
}

fn verify_release_signature(
    pubkey_hex: &str,
    container_id: &str,
    group_id: &str,
    share_id: u8,
    request_nonce_hex: &str,
    server_share_hex: &str,
    response_sig_hex: &str,
) -> Result<()> {
    let pubkey_bytes = hex::decode(pubkey_hex)
        .context("remote share server public key is not valid hex")?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow!("remote share server public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .context("remote share server public key is invalid")?;

    let sig_bytes = hex::decode(response_sig_hex)
        .context("remote share response signature is not valid hex")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("remote share response signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    let message = build_release_signature_message(
        container_id,
        group_id,
        share_id,
        request_nonce_hex,
        server_share_hex,
    );

    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|e| anyhow!("remote share response signature verification failed: {e}"))
}

fn build_release_signature_message(
    container_id: &str,
    group_id: &str,
    share_id: u8,
    request_nonce_hex: &str,
    server_share_hex: &str,
) -> String {
    format!(
        "norikey-remote-release-v1\ncontainer_id={}\ngroup_id={}\nshare_id={}\nrequest_nonce_hex={}\nserver_share_hex={}",
        container_id,
        group_id,
        share_id,
        request_nonce_hex.to_lowercase(),
        server_share_hex.to_lowercase(),
    )
}

fn build_http_client(timeout_ms: u64) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(1)))
        .build()
        .context("failed to build remote share HTTP client")
}

fn split_remote_factor_share(
    share: &SecretShare,
    quorum_n: u8,
    quorum_k: u8,
) -> Result<Vec<SecretShare>> {
    let sharks = Sharks(quorum_k);
    let dealer = sharks.dealer(share.as_bytes());
    Ok(dealer
        .take(quorum_n as usize)
        .map(|s| SecretShare::from_share(&s))
        .collect())
}

fn recover_remote_factor_share(subshares: &[SecretShare], quorum_k: u8) -> Result<SecretShare> {
    let sharks = Sharks(quorum_k);
    let parsed: Vec<Share> = subshares
        .iter()
        .map(|share| {
            Share::try_from(share.as_bytes())
                .map_err(anyhow::Error::msg)
                .context("failed to parse remote quorum subshare")
        })
        .collect::<Result<Vec<_>>>()?;

    let recovered = sharks
        .recover(parsed.as_slice())
        .map_err(|e| anyhow!("failed to recover remote factor share: {e}"))?;

    Ok(SecretShare::from_bytes(recovered))
}

fn derive_remote_auth_token(
    password: &str,
    header: &ContainerHeader,
    quorum: &RemoteQuorumPolicy,
) -> Result<[u8; 32]> {
    let salt = header
        .salt_bytes()
        .context("container header has invalid salt for remote authorization")?;
    let derived_salt = derive_remote_auth_salt(&salt, &quorum.group_id);
    let params = Params::new(header.argon_memory_kib, header.argon_iterations, 1, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters for remote authorization: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), &derived_salt, &mut out)
        .map_err(|e| anyhow!("argon2id failed while deriving remote authorization token: {e}"))?;
    Ok(out)
}

fn derive_remote_auth_salt(base_salt: &[u8], group_id: &str) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REMOTE_AUTH_CONTEXT);
    hasher.update(base_salt);
    hasher.update(group_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

fn derive_remote_auth_verifier(auth_token: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_token);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

fn binding_container_id(header: &ContainerHeader) -> Result<String> {
    let salt = header.salt_bytes()?;
    let nonce = header.nonce_bytes()?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"norikey/v1/container-id");
    hasher.update(header.format.as_bytes());
    hasher.update(&header.version.to_le_bytes());
    hasher.update(header.profile.as_bytes());
    hasher.update(&[header.policy.threshold]);

    for factor in &header.policy.enabled_factors {
        hasher.update(factor.as_str().as_bytes());
    }

    hasher.update(&header.argon_iterations.to_le_bytes());
    hasher.update(&header.argon_memory_kib.to_le_bytes());
    hasher.update(&salt);
    hasher.update(&nonce);

    Ok(hex::encode(hasher.finalize().as_bytes()))
}

fn random_hex(byte_len: usize) -> Result<String> {
    let mut buf = vec![0u8; byte_len];
    getrandom(&mut buf).context("failed to obtain randomness")?;
    Ok(hex::encode(buf))
}

#[derive(Debug, Serialize)]
struct EnrollRequest {
    action: String,
    container_id: String,
    group_id: String,
    share_id: u8,
    auth_verifier_hex: String,
    server_share_hex: String,
}

#[derive(Debug, Serialize)]
struct ReleaseRequest {
    action: String,
    container_id: String,
    group_id: String,
    share_id: u8,
    auth_token_hex: String,
    request_nonce_hex: String,
}

#[derive(Debug, Deserialize)]
struct GenericResponse {
    ok: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseResponse {
    ok: bool,
    error: Option<String>,
    container_id: String,
    group_id: String,
    share_id: u8,
    request_nonce_hex: Option<String>,
    server_share_hex: Option<String>,
    response_sig_key_id: Option<String>,
    response_sig_hex: Option<String>,
}
