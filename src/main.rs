#![no_main]
#![no_std]

extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod fixed_string;
mod flipper_app;
pub mod flipper_wallet_core;
pub mod hex;
pub mod keccak256;
pub mod pbkdf2;
pub mod ripemd160;
pub mod secp256k1;
pub mod sha256;
pub mod word_list;
use flipperzero_rt::{entry, manifest};

use core::ffi::CStr;

manifest!(
    name = "Flipper Zero Wallet",
    app_version = 1,
    has_icon = true,
    icon = "../assets/wallet-10x10.icon",
);

entry!(main);
fn main(_args: Option<&CStr>) -> i32 {
    flipper_app::app_main();
    0
}
