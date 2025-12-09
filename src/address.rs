extern crate alloc;

use alloc::vec::Vec;
use crate::sha256::Sha256;
use crate::secp256k1::PublicKey;
use crate::ripemd160::Ripemd160;
use crate::keccak256::Keccak256;

/// 支持的加密货币类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cryptocurrency {
    Bitcoin,
    Ethereum,
    Dogecoin,
    Litecoin,
    Dash,
    Ravencoin,
    Ripple,
}

impl Cryptocurrency {
    /// 获取币种的 BIP44 币种索引
    pub fn coin_type(&self) -> u32 {
        match self {
            Cryptocurrency::Bitcoin => 0,
            Cryptocurrency::Ethereum => 60,
            Cryptocurrency::Dogecoin => 3,
            Cryptocurrency::Litecoin => 2,
            Cryptocurrency::Dash => 5,
            Cryptocurrency::Ravencoin => 175,
            Cryptocurrency::Ripple => 144,
        }
    }
    
    /// 获取币种的图标文件名（不含扩展名）
    pub fn icon_name(&self) -> &'static str {
        match self {
            Cryptocurrency::Bitcoin => "BTC",
            Cryptocurrency::Ethereum => "ETH",
            Cryptocurrency::Dogecoin => "DOGE",
            Cryptocurrency::Litecoin => "LTC",
            Cryptocurrency::Dash => "DASH",
            Cryptocurrency::Ravencoin => "RVN",
            Cryptocurrency::Ripple => "XRP",
        }
    }
    
    /// 获取币种的显示名称
    pub fn display_name(&self) -> &'static str {
        match self {
            Cryptocurrency::Bitcoin => "Bitcoin",
            Cryptocurrency::Ethereum => "Ethereum",
            Cryptocurrency::Dogecoin => "Dogecoin",
            Cryptocurrency::Litecoin => "Litecoin",
            Cryptocurrency::Dash => "Dash",
            Cryptocurrency::Ravencoin => "Ravencoin",
            Cryptocurrency::Ripple => "Ripple",
        }
    }
    
    /// 获取地址版本字节
    pub fn address_prefix(&self) -> u8 {
        match self {
            Cryptocurrency::Bitcoin => 0x00,
            Cryptocurrency::Ethereum => 0x00, // ETH 不使用版本字节
            Cryptocurrency::Dogecoin => 0x1E,
            Cryptocurrency::Litecoin => 0x30,
            Cryptocurrency::Dash => 0x4C,
            Cryptocurrency::Ravencoin => 0x3C,
            Cryptocurrency::Ripple => 0x00, // XRP 使用特殊编码
        }
    }
}

/// RIPEMD-160 哈希函数
fn ripemd160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data)
}

/// Ripple 专用的 Base58 字母表
const RIPPLE_B58_DIGITS: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// 标准 Base58 字母表
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 编码（使用指定的字母表）
fn base58_encode_with_alphabet(data: &[u8], alphabet: &[u8; 58]) -> Vec<u8> {
    
    // 计算前导零的数量
    let mut leading_zeros = 0;
    for &byte in data {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    
    // 将数据转换为大数（使用 Vec<u8> 表示）
    let mut num = Vec::new();
    num.extend_from_slice(data);
    
    let mut result = Vec::new();
    
    // 重复除以 58
    while !num.is_empty() {
        let mut remainder = 0u16;
        let mut new_num = Vec::new();
        let mut started = false;
        
        for &byte in &num {
            remainder = (remainder << 8) | (byte as u16);
            if remainder >= 58 {
                started = true;
                new_num.push((remainder / 58) as u8);
                remainder %= 58;
            } else if started {
                new_num.push(0);
            }
        }
        
        result.push(alphabet[remainder as usize]);
        num = new_num;
    }
    
    // 添加前导 '1'
    for _ in 0..leading_zeros {
        result.push(b'1');
    }
    
    result.reverse();
    result
}

/// Base58 编码（使用标准字母表）
fn base58_encode(data: &[u8]) -> Vec<u8> {
    base58_encode_with_alphabet(data, BASE58_ALPHABET)
}

/// Ripple Base58 编码（使用 Ripple 专用字母表）
fn ripple_base58_encode(data: &[u8]) -> Vec<u8> {
    base58_encode_with_alphabet(data, RIPPLE_B58_DIGITS)
}

/// Base58Check 编码（带校验和，使用标准字母表）
fn base58check_encode(payload: &[u8]) -> Vec<u8> {
    // 计算校验和（双重 SHA-256 的前 4 字节）
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];
    
    // 组合 payload 和校验和
    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(payload);
    data.extend_from_slice(checksum);
    
    base58_encode(&data)
}

/// 生成 Bitcoin 类型地址（Base58Check）
pub fn generate_bitcoin_address(public_key: &PublicKey, prefix: u8) -> Result<Vec<u8>, &'static str> {
    // 压缩公钥
    let compressed_pubkey = public_key.serialize_compressed();
    
    // SHA-256
    let sha256_hash = Sha256::digest(&compressed_pubkey);
    
    // RIPEMD-160
    let ripemd160_hash = ripemd160(&sha256_hash);
    
    // 添加版本字节
    let mut versioned = Vec::with_capacity(21);
    versioned.push(prefix);
    versioned.extend_from_slice(&ripemd160_hash);
    
    // Base58Check 编码
    Ok(base58check_encode(&versioned))
}

/// 生成 Ethereum 地址
pub fn generate_ethereum_address(public_key: &PublicKey) -> Result<Vec<u8>, &'static str> {
    // 获取未压缩公钥（去掉 0x04 前缀）
    let uncompressed = public_key.serialize_uncompressed();
    let pubkey_no_prefix = &uncompressed[1..65];
    
    // Keccak-256 哈希
    let hash = Keccak256::digest(pubkey_no_prefix);
    
    // 取后 20 字节作为地址
    let mut address = Vec::with_capacity(42); // "0x" + 40 hex chars
    address.extend_from_slice(b"0x");
    
    // 转换为十六进制
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for &byte in &hash[12..32] {
        address.push(HEX_CHARS[(byte >> 4) as usize]);
        address.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    
    Ok(address)
}

/// 生成标准加密货币地址
pub fn generate_address(public_key: &PublicKey, cryptocurrency: Cryptocurrency) -> Result<Vec<u8>, &'static str> {
    match cryptocurrency {
        Cryptocurrency::Ethereum => generate_ethereum_address(public_key),
        Cryptocurrency::Ripple => {
            // Ripple 使用特殊的 Base58 编码和字母表
            let compressed_pubkey = public_key.serialize_compressed();
            let sha256_hash = Sha256::digest(&compressed_pubkey);
            let ripemd160_hash = ripemd160(&sha256_hash);
            
            // 计算校验和（双重 SHA-256 的前 4 字节）
            let hash1 = Sha256::digest(&ripemd160_hash);
            let hash2 = Sha256::digest(&hash1);
            let checksum = &hash2[..4];
            
            // 组合 payload 和校验和
            let mut data = Vec::with_capacity(24);
            data.push(0x00); // Ripple 版本字节
            data.extend_from_slice(&ripemd160_hash);
            data.extend_from_slice(checksum);
            
            // 使用 Ripple 专用的 Base58 编码
            Ok(ripple_base58_encode(&data))
        }
        _ => {
            // 其他币种使用标准 Base58Check
            generate_bitcoin_address(public_key, cryptocurrency.address_prefix())
        }
    }
}

