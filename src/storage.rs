//! Wallet storage module: encrypt/decrypt wallet data and persist to device
//! File format: [salt (16 bytes)] [iv (16 bytes)] [ciphertext (variable)]
//! Key derivation: PBKDF2-SHA256(passphrase, salt, iterations=100_000) -> 256-bit key
//! Encryption: AES-256-CBC with PKCS7 padding

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use crate::aes::{aes256_cbc_encrypt, aes256_cbc_decrypt};
use crate::pbkdf2::pbkdf2_hmac_sha256;
use core::convert::TryInto;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;

/// Wallet data structure for serialization
#[derive(Clone, Debug)]
pub struct WalletData {
    pub name: String,
    pub mnemonic: String,
    pub passphrase: String,
    pub word_count: u16, // 12, 15, 18, 21, or 24
}

impl WalletData {
    /// Serialize wallet to bytes (simple format: name_len, name, mnemonic_len, mnemonic, passphrase_len, passphrase, word_count)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        
        // Serialize name
        let name_bytes = self.name.as_bytes();
        out.push((name_bytes.len() & 0xFF) as u8);
        out.extend_from_slice(name_bytes);
        
        // Serialize mnemonic
        let mnemonic_bytes = self.mnemonic.as_bytes();
        out.push(((mnemonic_bytes.len() >> 8) & 0xFF) as u8);
        out.push((mnemonic_bytes.len() & 0xFF) as u8);
        out.extend_from_slice(mnemonic_bytes);
        
        // Serialize passphrase
        let passphrase_bytes = self.passphrase.as_bytes();
        out.push(((passphrase_bytes.len() >> 8) & 0xFF) as u8);
        out.push((passphrase_bytes.len() & 0xFF) as u8);
        out.extend_from_slice(passphrase_bytes);
        
        // Serialize word_count
        out.push(((self.word_count >> 8) & 0xFF) as u8);
        out.push((self.word_count & 0xFF) as u8);
        
        out
    }

    /// Deserialize wallet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() { return Err("Empty data"); }
        let mut pos = 0;

        // Deserialize name
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() { return Err("Truncated name"); }
        let name = String::from_utf8(data[pos..pos+name_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in name")?;
        pos += name_len;

        // Deserialize mnemonic
        if pos + 2 > data.len() { return Err("Truncated mnemonic length"); }
        let mnemonic_len = ((data[pos] as usize) << 8) | (data[pos+1] as usize);
        pos += 2;
        if pos + mnemonic_len > data.len() { return Err("Truncated mnemonic"); }
        let mnemonic = String::from_utf8(data[pos..pos+mnemonic_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in mnemonic")?;
        pos += mnemonic_len;

        // Deserialize passphrase
        if pos + 2 > data.len() { return Err("Truncated passphrase length"); }
        let passphrase_len = ((data[pos] as usize) << 8) | (data[pos+1] as usize);
        pos += 2;
        if pos + passphrase_len > data.len() { return Err("Truncated passphrase"); }
        let passphrase = String::from_utf8(data[pos..pos+passphrase_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in passphrase")?;
        pos += passphrase_len;

        // Deserialize word_count
        if pos + 2 > data.len() { return Err("Truncated word_count"); }
        let word_count = ((data[pos] as u16) << 8) | (data[pos+1] as u16);

        Ok(WalletData { name, mnemonic, passphrase, word_count })
    }
}

/// Encrypt and save wallet to file format
/// Returns: [salt (16)] [iv (16)] [ciphertext]
pub fn save_wallet(wallet: &WalletData, passphrase: &str, salt: &[u8;16], iv: &[u8;16]) -> Vec<u8> {
    let plaintext = wallet.to_bytes();
    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    let ciphertext = aes256_cbc_encrypt(&key, iv, &plaintext);
    
    let mut result = Vec::new();
    result.extend_from_slice(salt);
    result.extend_from_slice(iv);
    result.extend_from_slice(&ciphertext);
    result
}

/// Load and decrypt wallet from file format
/// Expects: [salt (16)] [iv (16)] [ciphertext]
pub fn load_wallet(data: &[u8], passphrase: &str) -> Result<WalletData, &'static str> {
    if data.len() < SALT_LEN + IV_LEN { 
        return Err("File too short for salt and IV");
    }
    
    let salt: &[u8;16] = data[0..16].try_into().map_err(|_| "Invalid salt")?;
    let iv: &[u8;16] = data[16..32].try_into().map_err(|_| "Invalid IV")?;
    let ciphertext = &data[32..];
    
    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    let plaintext = aes256_cbc_decrypt(&key, iv, ciphertext)?;
    
    WalletData::from_bytes(&plaintext)
}

/// Generate random salt and IV (caller should use Flipper TRNG)
pub fn generate_salt_and_iv() -> ([u8;16], [u8;16]) {
    // Placeholder: in actual use, caller will provide TRNG-generated bytes
    // For now return zeros; caller must override with real random data
    ([0u8;16], [0u8;16])
}
