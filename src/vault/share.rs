use std::convert::TryFrom;

use anyhow::{bail, Context, Result};
use sharks::{Share, Sharks};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vault::secret::{MasterSecret, MASTER_SECRET_LEN};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
    bytes: Vec<u8>,
}

impl SecretShare {
    pub fn from_share(share: &Share) -> Self {
        Self {
            bytes: Vec::from(share),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub fn split_master_secret(
    secret: &MasterSecret,
    share_count: u8,
    threshold: u8,
) -> Result<Vec<SecretShare>> {
    if threshold == 0 {
        bail!("threshold must be greater than zero");
    }

    if share_count < threshold {
        bail!(
            "share count {} must be greater than or equal to threshold {}",
            share_count,
            threshold
        );
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret.as_bytes());
    let shares = dealer
        .take(share_count as usize)
        .map(|share| SecretShare::from_share(&share))
        .collect();

    Ok(shares)
}

pub fn recover_master_secret(shares: &[SecretShare], threshold: u8) -> Result<MasterSecret> {
    if shares.len() < threshold as usize {
        bail!(
            "need at least {} shares to recover the master secret, got {}",
            threshold,
            shares.len()
        );
    }

    let sharks = Sharks(threshold);
    let parsed_shares: Vec<Share> = shares
        .iter()
        .map(|share| {
            Share::try_from(share.as_bytes())
                .map_err(anyhow::Error::msg)
                .context("failed to parse serialized share")
        })
        .collect::<Result<Vec<_>>>()?;

    let recovered = sharks
        .recover(parsed_shares.as_slice())
        .map_err(|e| anyhow::anyhow!("failed to recover master secret from shares: {e}"))?;

    if recovered.len() != MASTER_SECRET_LEN {
        bail!(
            "recovered secret has invalid length {}, expected {}",
            recovered.len(),
            MASTER_SECRET_LEN
        );
    }

    let mut secret = [0u8; MASTER_SECRET_LEN];
    secret.copy_from_slice(&recovered);
    Ok(MasterSecret::new(secret))
}
