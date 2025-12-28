extern crate alloc;
use alloc::vec::Vec;

pub fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    buf.resize(len, 0u8);
    
    unsafe {
        furi_hal_random_fill_buf(buf.as_mut_ptr(), len as u32);
    }
    
    buf
}

pub fn get_random_iv() -> [u8;16] {
    let bytes = get_random_bytes(16);
    let mut iv = [0u8;16];
    iv.copy_from_slice(&bytes[..16]);
    iv
}

pub fn get_random_salt() -> [u8;16] {
    let bytes = get_random_bytes(16);
    let mut salt = [0u8;16];
    salt.copy_from_slice(&bytes[..16]);
    salt
}

pub fn get_entropy(bits: usize) -> Result<Vec<u8>, &'static str> {
    match bits {
        128 | 160 | 192 | 256 => {
            let bytes_needed = bits / 8;
            Ok(get_random_bytes(bytes_needed))
        }
        _ => Err("Invalid entropy size; use 128, 160, 192, or 256 bits"),
    }
}

extern "C" {
    pub fn furi_hal_random_fill_buf(buf: *mut u8, len: u32);
}
