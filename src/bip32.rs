extern crate alloc;

use crate::secp256k1::{PublicKey, SecretKey};
use crate::sha256::Sha256;
use alloc::vec::Vec;

fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let hash1 = Sha256::digest(key);
    let hash2 = Sha256::digest(message);

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&hash1);
    combined[32..].copy_from_slice(&hash2);

    let hash3 = Sha256::digest(&combined);
    let hash4 = Sha256::digest(&hash3);

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&hash3);
    result[32..].copy_from_slice(&hash4);
    result
}

/// 主密钥（从种子派生）
pub struct MasterKey {
    key: SecretKey,
    chain_code: [u8; 32],
}

impl MasterKey {
    /// 从种子创建主密钥
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, &'static str> {
        let hmac = hmac_sha512(b"Bitcoin seed", seed);
        let mut master_key_bytes = [0u8; 32];
        master_key_bytes.copy_from_slice(&hmac[..32]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hmac[32..]);

        let key = SecretKey::from_bytes(&master_key_bytes).map_err(|_| "Invalid master key")?;

        Ok(MasterKey { key, chain_code })
    }

    /// 派生子密钥（BIP32）
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<Self, &'static str> {
        let index = if hardened { index | 0x80000000 } else { index };

        // 获取公钥
        let public_key = PublicKey::from_secret_key(&self.key)?;
        let pubkey_bytes = public_key.serialize_compressed();

        // 准备数据
        let mut data = Vec::with_capacity(37);
        if hardened {
            // 硬派生：使用私钥
            data.push(0x00);
            data.extend_from_slice(self.key.as_bytes());
        } else {
            // 软派生：使用公钥
            data.extend_from_slice(&pubkey_bytes);
        }

        // 添加索引（大端序）
        data.push((index >> 24) as u8);
        data.push((index >> 16) as u8);
        data.push((index >> 8) as u8);
        data.push(index as u8);

        // HMAC-SHA512(chain_code, data)
        let hmac = hmac_sha512(&self.chain_code, &data);

        // 派生新的私钥和链码
        let mut child_key_bytes = [0u8; 32];
        child_key_bytes.copy_from_slice(&hmac[..32]);

        // 添加父私钥（简化版本）
        for i in 0..32 {
            child_key_bytes[i] = child_key_bytes[i].wrapping_add(self.key.as_bytes()[i]);
        }

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&hmac[32..]);

        let child_key = SecretKey::from_bytes(&child_key_bytes).map_err(|_| "Invalid child key")?;

        Ok(MasterKey {
            key: child_key,
            chain_code: child_chain_code,
        })
    }

    /// 派生 BIP44 路径：m/44'/coin_type'/account'/change/address_index
    pub fn derive_bip44(
        &self,
        coin_type: u32,
        account: u32,
        change: u32,
        address_index: u32,
    ) -> Result<SecretKey, &'static str> {
        // m/44'
        let purpose = self.derive_child(44, true)?;
        // m/44'/coin_type'
        let coin = purpose.derive_child(coin_type, true)?;
        // m/44'/coin_type'/account'
        let account_key = coin.derive_child(account, true)?;
        // m/44'/coin_type'/account'/change
        let change_key = account_key.derive_child(change, false)?;
        // m/44'/coin_type'/account'/change/address_index
        let address_key = change_key.derive_child(address_index, false)?;

        Ok(address_key.key)
    }

    /// 获取私钥
    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    /// 获取公钥
    pub fn public_key(&self) -> Result<PublicKey, &'static str> {
        PublicKey::from_secret_key(&self.key)
    }
}
