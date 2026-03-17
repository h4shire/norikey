# NoriKey

NoriKey is a Rust-based prototype for multi-factor secret sealing and recovery using threshold cryptography plus an optional mandatory remote release gate.

The project is designed for scenarios where a secret should only be recoverable when a configurable set of local factors is present and, optionally, when one or more remote servers are still reachable and willing to release a bound remote factor.

## Current status

This repository is an active prototype and hardening project. The current implementation already supports end-to-end `init-header`, `seal`, and `unlock` flows, but the codebase is still evolving and should be treated as pre-1.0 software.

Implemented building blocks currently include:

- threshold-based local factor policy
- optional mandatory remote release gate (`remote_mode: mandatory_gate`)
- signed remote release responses
- request nonce binding and replay cache on the PHP remote server
- YubiKey lane model with up to two active YubiKey lanes from a larger device pool
- lane-specific distinct-device enforcement
- dead-sector factor
- steganographic carrier factor
- hardware identifier factor
- brain key factor
- sealed local configuration overlay via `config.sealed`

## High-level architecture

NoriKey separates recovery into two layers:

1. **Local threshold recovery**
   A configurable subset of local factors reconstructs the local master secret.

2. **Optional mandatory remote gate**
   When `remote_mode: mandatory_gate` is enabled, a remote release is required in addition to the local threshold. In this mode, the final container key is derived from:
   - the recovered local master secret
   - remote gate material
   - the header salt

This means the remote factor is not just “one more Shamir share”, but a separate mandatory gate.

## Supported factor types

### Local factors

- `hardware_id`
- `brain_key`
- `steganography`
- `dead_sector`
- `yubi_key_1`
- `yubi_key_2`

### Remote factor

- `remote_mode: mandatory_gate`

## YubiKey model

The current YubiKey model uses **two active logical lanes** backed by a larger pool of physical YubiKeys.

- `yubi_key_1` and `yubi_key_2` are the active YubiKey factors.
- Each lane can enroll one or more physical devices.
- When `yubikey_require_distinct_devices: true` is enabled, the same physical YubiKey serial cannot satisfy both active lanes.
- During unlock, enrolled devices are tried in the stored lane-specific order.

This is an intermediate architecture on the way to a more generic pool model, but it already supports real-world two-device workflows.

## Remote server model

The remote factor is backed by one or more PHP endpoints (`server/remote_share.php`).

Each server stores only a minimal remote record and returns a signed release response. The client verifies:

- response nonce binding
- server key identity
- Ed25519 response signature
- release payload consistency

The current server implementation also contains:

- replay tracking for request nonces
- record locking for safer concurrent release handling

## Repository layout

```text
src/
  main.rs                 CLI entrypoints and orchestration
  config.rs               local config loading, sealed overlay handling
  policy.rs               factor and threshold policy model
  session.rs              interactive session state
  factors/                factor providers
  vault/                  header, share, crypto, payload code

server/
  remote_share.php        PHP remote share endpoint
  generate_remote_signing_seed.php

docs/
  phase-a-remote-gating.md
```

## Typical workflows

### 1. Initialize a container header

```bash
cargo run -- init-header --container vault.nk --config config.yaml
```

### 2. Seal a payload

```bash
cargo run -- seal --container vault.nk --input secret.txt --config config.yaml
```

### 3. Unlock a payload

```bash
cargo run -- unlock --container vault.nk --output recovered.txt --config config.yaml
```

## Configuration model

### Local threshold

`threshold` applies to the **local enabled factors**.

Example:

```yaml
threshold: 5
enabled_factors:
  - hardware_id
  - brain_key
  - steganography
  - dead_sector
  - yubi_key_1
  - yubi_key_2
```

With the configuration above:

- local recovery requires `5/6`
- the four non-YubiKey factors alone are not enough
- therefore at least **one YubiKey** must contribute

### Mandatory remote gate

```yaml
remote_mode: "mandatory_gate"
remote_quorum_k: 2
remote_selection_mode: "random_subset"
remote_max_active_servers: 3
```

When `remote_mode` is enabled, local recovery alone is not sufficient. A valid remote release must also succeed.

## Important operational notes

### 1. `config.sealed` overrides `config.yaml`

If `config.sealed` exists, its values are merged on top of `config.yaml` after decryption with the brain key.

If runtime behavior does not match the visible YAML, always check whether `config.sealed` contains older values.

### 2. Header-embedded remote state matters

Unlock uses remote server information embedded in the container header. Changing `config.yaml` after `init-header` or `seal` does not retroactively change the remote server pool already stored in the container.

### 3. YubiKey tooling matters

The real YubiKey path depends on `ykman`. If `ykman list` hangs or returns nothing, the issue is outside NoriKey and typically related to:

- USB reconnect issues
- Hub/adapter problems
- local `ykman` installation issues

## Example configuration

```yaml
argon_iterations: 4
argon_memory: 65536
threshold: 5

enabled_factors:
  - hardware_id
  - brain_key
  - steganography
  - dead_sector
  - yubi_key_1
  - yubi_key_2

hash_profile: "blake3"
rng_mode: "paranoia"
os_rng_required: true
external_entropy_required: false
external_entropy_mode: "mix"
external_entropy_min_bytes: 64

stego_carrier_png: "./assets/stego-carrier.png"
stego_output_png: "./assets/stego-carrier.norikey.png"

dead_sector_device: "./dead-sector.bin"
dead_sector_offset: 8192

remote_mode: "mandatory_gate"
remote_quorum_k: 2
remote_selection_mode: "random_subset"
remote_max_active_servers: 3
remote_request_timeout_ms: 3500
remote_retry_backoff_ms: 1200
remote_require_brain_key_auth: true
remote_auth_mode: "brain_key_token_v1"
remote_release_mode: "remote_subshare_v1"
remote_require_distinct_servers: true

yubikey_mode: "auto"
yubikey_binary: "ykman"
yubikey_pool_max_active_factors: 2
yubikey_a_slot: 1
yubikey_b_slot: 2
yubikey_require_distinct_devices: true

remote_servers:
  - id: "srv-a"
    endpoint: "https://srv-01.example.com/remote_share.php"
    weight: 100
  - id: "srv-b"
    endpoint: "https://srv-02.example.com/remote_share.php"
    weight: 100
  - id: "srv-c"
    endpoint: "https://srv-03.example.com/remote_share.php"
    weight: 100
  - id: "srv-d"
    endpoint: "https://srv-04.example.com/remote_share.php"
    weight: 100
```

## Security and design notes

- This repository is intended for advanced users who understand the trade-off between recoverability and strictness.
- A global threshold alone cannot express “this one factor must always be present”; that is why the remote factor is modeled as a separate gate.
- The current YubiKey implementation is significantly improved compared with the original A/B-only model, but it is still on the path toward a more general pool design.
- The steganographic factor is currently practical for local PNG carrier use, but not yet designed to survive aggressive social-media transcoding.

## Roadmap focus

The most relevant next steps are:

- tighten remaining UI/diagnostic consistency
- continue moving YubiKey lane logic toward a fully generic pool model
- improve test coverage and negative-path automation
- document remote deployment and operator workflows more completely

## License

See `LICENSE`.
