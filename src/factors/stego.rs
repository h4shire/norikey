use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use image::{DynamicImage, ImageFormat};

use crate::{
    config::LocalConfig,
    policy::FactorKind,
    vault::{
        header::{ContainerHeader, ShareBinding},
        share::SecretShare,
    },
};

use super::FactorProvider;

const PROTECTION_STEGO_PNG_LSB_V1: &str = "steganography_png_lsb_v1";
const STEGO_MAGIC: &[u8; 5] = b"NKSG1";
const STEGO_HEADER_LEN: usize = 9;

pub struct StegoProvider;

impl FactorProvider for StegoProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::Steganography
    }

    fn store_share(
        &self,
        share_id: u8,
        share: &SecretShare,
        _header: &ContainerHeader,
        config: &LocalConfig,
    ) -> Result<ShareBinding> {
        let carrier_path = config
            .resolved_stego_carrier_path()
            .ok_or_else(|| anyhow!("steganography factor requires 'stego_carrier_png' in config"))?;
        let output_path = config
            .resolved_stego_output_path()
            .ok_or_else(|| anyhow!("steganography factor requires a valid stego output path"))?;

        let image = image::open(&carrier_path)
            .with_context(|| format!("failed to open steganography carrier image {}", carrier_path.display()))?;

        embed_share_into_png(image, share)
            .with_context(|| format!("failed to embed steganography share into {}", carrier_path.display()))?
            .save_with_format(&output_path, ImageFormat::Png)
            .with_context(|| format!("failed to write steganography output image {}", output_path.display()))?;

        Ok(ShareBinding {
            factor: self.kind(),
            share_id,
            locator: Some(output_path.display().to_string()),
            protection: PROTECTION_STEGO_PNG_LSB_V1.to_string(),
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

        if binding.protection != PROTECTION_STEGO_PNG_LSB_V1 {
            bail!(
                "steganography provider only supports '{}' in this build",
                PROTECTION_STEGO_PNG_LSB_V1
            );
        }

        let png_path = resolve_stego_locator(binding.locator.as_deref(), config)
            .ok_or_else(|| anyhow!("steganography binding does not contain a usable PNG locator"))?;

        let image = image::open(&png_path)
            .with_context(|| format!("failed to open steganography image {}", png_path.display()))?;
        let share = extract_share_from_png(image)
            .with_context(|| format!("failed to extract steganography share from {}", png_path.display()))?;
        Ok(Some(share))
    }
}

fn resolve_stego_locator(locator: Option<&str>, config: &LocalConfig) -> Option<PathBuf> {
    match locator {
        Some(value) if !value.trim().is_empty() => Some(PathBuf::from(value)),
        _ => config.resolved_stego_output_path(),
    }
}

fn embed_share_into_png(image: DynamicImage, share: &SecretShare) -> Result<DynamicImage> {
    let mut rgba = image.to_rgba8();
    let raw = rgba.as_mut();

    let record = build_record(share);
    let required_bits = record.len() * 8;
    if required_bits > raw.len() {
        bail!(
            "steganography carrier capacity is too small: need {} bytes of pixel data, found {}",
            required_bits,
            raw.len()
        );
    }

    for (bit_index, bit) in bytes_to_bits(&record).into_iter().enumerate() {
        raw[bit_index] = (raw[bit_index] & 0b1111_1110) | bit;
    }

    Ok(DynamicImage::ImageRgba8(rgba))
}

fn extract_share_from_png(image: DynamicImage) -> Result<SecretShare> {
    let rgba = image.to_rgba8();
    let raw = rgba.as_raw();

    let header_bytes = read_bytes_from_lsb(raw, 0, STEGO_HEADER_LEN)
        .context("failed to read steganography record header")?;
    if &header_bytes[..STEGO_MAGIC.len()] != STEGO_MAGIC {
        bail!("steganography image does not contain a NoriKey stego marker");
    }

    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&header_bytes[STEGO_MAGIC.len()..STEGO_HEADER_LEN]);
    let share_len = u32::from_be_bytes(len_buf) as usize;
    if share_len == 0 {
        bail!("steganography image contains an empty share record");
    }

    let total_len = STEGO_HEADER_LEN + share_len;
    let record_bytes = read_bytes_from_lsb(raw, 0, total_len)
        .context("failed to read complete steganography record")?;
    let share_bytes = &record_bytes[STEGO_HEADER_LEN..];
    Ok(SecretShare::from_bytes(share_bytes.to_vec()))
}

fn build_record(share: &SecretShare) -> Vec<u8> {
    let mut record = Vec::with_capacity(STEGO_HEADER_LEN + share.as_bytes().len());
    record.extend_from_slice(STEGO_MAGIC);
    record.extend_from_slice(&(share.as_bytes().len() as u32).to_be_bytes());
    record.extend_from_slice(share.as_bytes());
    record
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for shift in (0..8).rev() {
            out.push((byte >> shift) & 1);
        }
    }
    out
}

fn read_bytes_from_lsb(raw: &[u8], offset_bytes: usize, len: usize) -> Result<Vec<u8>> {
    let start_bit = offset_bytes * 8;
    let required_bits = len * 8;
    if start_bit + required_bits > raw.len() {
        bail!(
            "steganography image does not contain enough pixel data: need {}, found {}",
            start_bit + required_bits,
            raw.len()
        );
    }

    let mut out = Vec::with_capacity(len);
    for chunk in raw[start_bit..start_bit + required_bits].chunks_exact(8) {
        let mut value = 0u8;
        for bit in chunk {
            value = (value << 1) | (bit & 1);
        }
        out.push(value);
    }
    Ok(out)
}
