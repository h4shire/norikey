use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "norikey",
    version,
    about = "Threshold-secured resilient secret recovery and hardware-anchored unlock orchestration"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Recover the container key from configured factors and optionally decrypt the payload.
    Unlock(UnlockArgs),
    /// Print the parsed header of a NoriKey container.
    Inspect(InspectArgs),
    /// Create an empty container with a NoriKey header for inspection and testing.
    InitHeader(InitHeaderArgs),
    /// Create a NoriKey container with an encrypted payload.
    Seal(SealArgs),
    /// Encrypt a local sensitive config overlay into config.sealed.
    SealConfig(SealConfigArgs),
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// NoriKey container file.
    #[arg(long)]
    pub container: PathBuf,

    /// Optional path to the local YAML configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Optional output path for the decrypted payload.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// NoriKey container file.
    #[arg(long)]
    pub container: PathBuf,
}

#[derive(Debug, Args)]
pub struct InitHeaderArgs {
    /// NoriKey container file to create.
    #[arg(long)]
    pub container: PathBuf,

    /// Optional path to the local YAML configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SealArgs {
    /// Input file to encrypt into the container payload.
    #[arg(long)]
    pub input: PathBuf,

    /// NoriKey container file to create.
    #[arg(long)]
    pub container: PathBuf,

    /// Optional path to the local YAML configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SealConfigArgs {
    /// Path to the plaintext sensitive YAML overlay file.
    #[arg(long)]
    pub source: PathBuf,

    /// Optional path to the local base YAML configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Output path for the encrypted sealed config. Defaults to sibling config.sealed.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Optional Argon2 iterations for the sealed config key.
    #[arg(long)]
    pub iterations: Option<u32>,

    /// Optional Argon2 memory (KiB) for the sealed config key.
    #[arg(long)]
    pub memory_kib: Option<u32>,
}
