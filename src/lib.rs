#![no_std]
extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

pub mod address;
pub mod aes;
pub mod bip32;
pub mod bip39;
pub mod fixed_string;
pub mod flipper_app;
pub mod flipper_wallet_core;
pub mod hex;
pub mod keccak256;
pub mod pbkdf2;
pub mod qrcodegen;
pub mod ripemd160;
pub mod secp256k1;
pub mod sha256;
pub mod storage;
pub mod trng;
pub mod word_list;

#[allow(dead_code)]
fn main(_args: *mut u8) -> i32 {
    flipper_app::app_main();
    0
}
