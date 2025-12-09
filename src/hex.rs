extern crate alloc;

use alloc::vec::Vec;
use crate::fixed_string::FixedString;

/// 将字节数组编码为十六进制字符串
pub fn encode(data: &[u8]) -> FixedString<256> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = FixedString::new();
    
    for &byte in data {
        let high = (byte >> 4) as usize;
        let low = (byte & 0x0f) as usize;
        let _ = result.push(HEX_CHARS[high] as char);
        let _ = result.push(HEX_CHARS[low] as char);
    }
    
    result
}

/// 将字节数组编码为十六进制字符串（使用固定大小字符串）
pub fn encode_to_fixed<const N: usize>(data: &[u8]) -> Result<FixedString<N>, &'static str> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = FixedString::new();
    
    for &byte in data {
        let high = (byte >> 4) as usize;
        let low = (byte & 0x0f) as usize;
        result.push(HEX_CHARS[high] as char)?;
        result.push(HEX_CHARS[low] as char)?;
    }
    
    Ok(result)
}

/// 将十六进制字符串解码为字节数组
pub fn decode(hex: &str) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();
    let chars: Vec<char> = hex.chars().collect();
    
    for chunk in chars.chunks(2) {
        if chunk.len() != 2 {
            return Err("Invalid hex string length");
        }
        
        let high = hex_char_to_value(chunk[0])?;
        let low = hex_char_to_value(chunk[1])?;
        result.push((high << 4) | low);
    }
    
    Ok(result)
}

fn hex_char_to_value(c: char) -> Result<u8, &'static str> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err("Invalid hex character"),
    }
}

