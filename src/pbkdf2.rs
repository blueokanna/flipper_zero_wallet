extern crate alloc;

use alloc::vec::Vec;
use crate::sha256::Sha256;

/// HMAC-SHA256 实现
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // 准备密钥（如果长度 > 64，先哈希）
    let mut hmac_key = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        hmac_key[..32].copy_from_slice(&hash);
    } else {
        hmac_key[..key.len()].copy_from_slice(key);
    }
    
    // 创建内部和外部填充
    let mut i_key_pad = [0x36u8; 64];
    let mut o_key_pad = [0x5cu8; 64];
    
    for i in 0..64 {
        i_key_pad[i] ^= hmac_key[i];
        o_key_pad[i] ^= hmac_key[i];
    }
    
    // 内部哈希：HASH(i_key_pad || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&i_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();
    
    // 外部哈希：HASH(o_key_pad || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&o_key_pad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// PBKDF2-HMAC-SHA256 实现
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let block_count = (output.len() + 31) / 32;
    
    for i in 0..block_count {
        // 准备 salt || block_number (big-endian)
        let mut u_salt = Vec::with_capacity(salt.len() + 4);
        u_salt.extend_from_slice(salt);
        let block_num = (i + 1) as u32;
        u_salt.push((block_num >> 24) as u8);
        u_salt.push((block_num >> 16) as u8);
        u_salt.push((block_num >> 8) as u8);
        u_salt.push(block_num as u8);
        
        // U1 = HMAC(password, salt || block_number)
        let mut u = hmac_sha256(password, &u_salt);
        let mut t = u;
        
        // U2, U3, ..., U_iterations
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            // T = U1 XOR U2 XOR ... XOR U_iterations
            for j in 0..32 {
                t[j] ^= u[j];
            }
        }
        
        // 复制到输出
        let start = i * 32;
        let end = core::cmp::min(start + 32, output.len());
        output[start..end].copy_from_slice(&t[..end - start]);
    }
}

/// 从助记词和密码短语生成种子（BIP39）
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    
    // 构建 salt: "mnemonic" + passphrase
    let mut salt = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());
    
    pbkdf2_hmac_sha256(mnemonic.as_bytes(), &salt, 2048, &mut seed);
    seed
}

