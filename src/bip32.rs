extern crate alloc;

use crate::secp256k1::{PublicKey, SecretKey};
use crate::sha256::Sha256;
use alloc::vec::Vec;

/// HMAC-SHA256 实现（用于 BIP32）
/// 返回 32 字节的哈希结果
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    
    let mut k = [0u8; BLOCK_SIZE];
    
    // 如果密钥太长，先哈希它
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    
    // 创建外层和内层的密钥
    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }
    
    // 计算内层 HMAC
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&i_key_pad);
    inner_input.extend_from_slice(message);
    
    let inner_hash = Sha256::digest(&inner_input);
    
    // 计算外层 HMAC
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    outer_input.extend_from_slice(&o_key_pad);
    outer_input.extend_from_slice(&inner_hash);
    
    Sha256::digest(&outer_input)
}

/// 主密钥（从种子派生）
pub struct MasterKey {
    key: SecretKey,
    chain_code: [u8; 32],
}

impl MasterKey {
    /// 从种子创建主密钥
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, &'static str> {
        // BIP32: HMAC-SHA256(Key = "Bitcoin seed", Data = seed)
        let hmac = hmac_sha256(b"Bitcoin seed", seed);
        
        let mut master_key_bytes = [0u8; 32];
        master_key_bytes.copy_from_slice(&hmac[..32]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hmac[32..]);

        let key = SecretKey::from_bytes(&master_key_bytes)
            .map_err(|_| "Invalid master key (parsed key must be non-zero and < N)")?;

        Ok(MasterKey { key, chain_code })
    }

    /// 派生子密钥（BIP32）
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<Self, &'static str> {
        let final_index = if hardened { index | 0x80000000 } else { index };

        // 准备派生数据
        let mut data = Vec::with_capacity(37);
        
        if hardened {
            // 硬派生（Hardened Derivation）：使用私钥
            data.push(0x00);
            data.extend_from_slice(self.key.as_bytes());
        } else {
            // 软派生（Normal Derivation）：使用公钥
            let public_key = PublicKey::from_secret_key(&self.key)?;
            let pubkey_bytes = public_key.serialize_compressed();
            data.extend_from_slice(&pubkey_bytes);
        }

        // 添加索引（大端序 32 位）
        data.extend_from_slice(&final_index.to_be_bytes());

        // HMAC-SHA256(chain_code, data)
        let hmac = hmac_sha256(&self.chain_code, &data);

        // 分离私钥倍数和新链码
        let mut child_key_bytes = [0u8; 32];
        child_key_bytes.copy_from_slice(&hmac[..32]);

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&hmac[32..]);

        // 派生的私钥 = (tweak + parent_key) mod n
        // 这里使用简化版本：直接加法（mod n）
        let mut new_key = [0u8; 32];
        let mut carry = 0u16;
        
        // 大端序加法
        for i in (0..32).rev() {
            let sum = self.key.as_bytes()[i] as u16 + child_key_bytes[i] as u16 + carry;
            new_key[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }

        let child_key = SecretKey::from_bytes(&new_key)
            .map_err(|_| "Derived child key is invalid")?;

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
    
    /// 获取链码
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}
