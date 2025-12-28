extern crate alloc;

use alloc::vec::Vec;
use crate::sha256::Sha256;
use crate::word_list::{word_at, index_of};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicType {
    Words12,  // 128 bits entropy
    Words15,  // 160 bits entropy
    Words18,  // 192 bits entropy
    Words21,  // 224 bits entropy
    Words24,  // 256 bits entropy
}

impl MnemonicType {
    /// 获取词数
    pub fn word_count(&self) -> usize {
        match self {
            MnemonicType::Words12 => 12,
            MnemonicType::Words15 => 15,
            MnemonicType::Words18 => 18,
            MnemonicType::Words21 => 21,
            MnemonicType::Words24 => 24,
        }
    }
    
    pub fn entropy_bits(&self) -> usize {
        match self {
            MnemonicType::Words12 => 128,
            MnemonicType::Words15 => 160,
            MnemonicType::Words18 => 192,
            MnemonicType::Words21 => 224,
            MnemonicType::Words24 => 256,
        }
    }
    
    pub fn entropy_bytes(&self) -> usize {
        self.entropy_bits() / 8
    }
}

pub fn entropy_to_mnemonic(entropy: &[u8], mnemonic_type: MnemonicType) -> Result<Vec<&'static str>, &'static str> {
    if entropy.len() != mnemonic_type.entropy_bytes() {
        return Err("Invalid entropy length");
    }
    
    let hash = Sha256::digest(entropy);
    let checksum_bits = mnemonic_type.word_count() / 3;
    let checksum_byte = hash[0];
    
    let total_bits = mnemonic_type.entropy_bits() + checksum_bits;
    let mut bits = Vec::with_capacity(total_bits);
    
    for &byte in entropy {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1);
        }
    }
    
    for i in 0..checksum_bits {
        bits.push((checksum_byte >> (7 - i)) & 1);
    }
    
    let mut words = Vec::new();
    for chunk in bits.chunks(11) {
        let mut index = 0u16;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit == 1 {
                index |= 1 << (10 - i);
            }
        }
        
        if index >= 2048 {
            return Err("Invalid word index");
        }
        
        let word = word_at(index as usize).ok_or("Invalid word index")?;
        words.push(word);
    }
    
    Ok(words)
}

pub fn mnemonic_to_entropy(words: &[&str]) -> Result<Vec<u8>, &'static str> {
    if words.len() < 12 || words.len() > 24 || words.len() % 3 != 0 {
        return Err("Invalid mnemonic word count");
    }
    
    let mut indices = Vec::new();
    for word in words {
        let index = index_of(word).ok_or("Invalid word")?;
        indices.push(index as u16);
    }
    
    let mut bits = Vec::new();
    for index in &indices {
        for i in 0..11 {
            bits.push(((*index >> (10 - i)) & 1) as u8);
        }
    }
    
    let entropy_bits = words.len() * 11 - words.len() / 3;
    let checksum_bits = words.len() / 3;
    
    if bits.len() < entropy_bits + checksum_bits {
        return Err("Invalid bit length");
    }
    
    // 提取熵
    let entropy_bytes = entropy_bits / 8;
    let mut entropy = Vec::with_capacity(entropy_bytes);
    
    for i in 0..entropy_bytes {
        let mut byte = 0u8;
        for j in 0..8 {
            if bits[i * 8 + j] == 1 {
                byte |= 1 << (7 - j);
            }
        }
        entropy.push(byte);
    }
    
    let hash = Sha256::digest(&entropy);
    let expected_checksum = hash[0];
    
    let mut actual_checksum = 0u8;
    for i in 0..checksum_bits {
        if bits[entropy_bits + i] == 1 {
            actual_checksum |= 1 << (7 - i);
        }
    }
    
    let mask = 0xff << (8 - checksum_bits);
    if (expected_checksum & mask) != (actual_checksum & mask) {
        return Err("Invalid checksum");
    }
    
    Ok(entropy)
}

pub fn generate_mnemonic(mnemonic_type: MnemonicType, entropy: &[u8]) -> Result<Vec<&'static str>, &'static str> {
    if entropy.len() != mnemonic_type.entropy_bytes() {
        return Err("Invalid entropy length");
    }
    entropy_to_mnemonic(entropy, mnemonic_type)
}

pub fn validate_mnemonic(words: &[&str]) -> bool {
    mnemonic_to_entropy(words).is_ok()
}

