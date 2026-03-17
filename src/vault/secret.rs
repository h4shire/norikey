use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MASTER_SECRET_LEN: usize = 32;
pub const CONTAINER_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret(pub(crate) [u8; MASTER_SECRET_LEN]);

impl MasterSecret {
    pub fn new(bytes: [u8; MASTER_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_SECRET_LEN] {
        &self.0
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContainerKey(pub(crate) [u8; CONTAINER_KEY_LEN]);

impl ContainerKey {
    pub fn new(bytes: [u8; CONTAINER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; CONTAINER_KEY_LEN] {
        &self.0
    }
}
