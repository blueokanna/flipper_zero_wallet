#![no_std]

extern crate alloc;
extern crate flipperzero_alloc; 
extern crate flipperzero_rt;

mod flipper_app;
pub mod sha256;
pub mod fixed_string;
pub mod hex;
pub mod pbkdf2;
pub mod bip39;
pub mod secp256k1;
pub mod bip32;
pub mod address;
pub mod word_list;
pub mod flipper_wallet_core;
pub mod ripemd160;
pub mod keccak256;

#[no_mangle]
pub extern "C" fn flipper_zero_wallet(_args: *mut u8) -> i32 {
    flipper_app::app_main()
}
