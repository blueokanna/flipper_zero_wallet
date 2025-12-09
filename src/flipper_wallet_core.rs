extern crate alloc;

use crate::address::{generate_address, Cryptocurrency};
use crate::bip32::MasterKey;
use crate::bip39::{entropy_to_mnemonic, mnemonic_to_entropy, validate_mnemonic, MnemonicType};
use crate::fixed_string::FixedString;
use crate::pbkdf2::mnemonic_to_seed;
use crate::secp256k1::PublicKey;
use alloc::vec::Vec;

pub type WalletResult<T> = Result<T, WalletError>;

#[derive(Clone, Copy)]
pub enum WalletError {
    InvalidEntropy,
    InvalidMnemonic,
    InvalidSeed,
    InvalidKey,
    DerivationFailed,
    AddressTooLong,
    InvalidPath,
    IndexOutOfBounds,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::InvalidEntropy => write!(f, "Invalid entropy"),
            WalletError::InvalidMnemonic => write!(f, "Invalid mnemonic"),
            WalletError::InvalidSeed => write!(f, "Invalid seed"),
            WalletError::InvalidKey => write!(f, "Invalid key"),
            WalletError::DerivationFailed => write!(f, "Key derivation failed"),
            WalletError::AddressTooLong => write!(f, "Address too long"),
            WalletError::InvalidPath => write!(f, "Invalid derivation path"),
            WalletError::IndexOutOfBounds => write!(f, "Index out of bounds"),
        }
    }
}

impl From<&'static str> for WalletError {
    fn from(s: &'static str) -> Self {
        match s {
            s if s.contains("entropy") => WalletError::InvalidEntropy,
            s if s.contains("mnemonic") => WalletError::InvalidMnemonic,
            s if s.contains("seed") => WalletError::InvalidSeed,
            s if s.contains("key") => WalletError::InvalidKey,
            s if s.contains("derivation") => WalletError::DerivationFailed,
            s if s.contains("path") => WalletError::InvalidPath,
            _ => WalletError::InvalidKey,
        }
    }
}

impl core::fmt::Debug for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

fn u32_to_string(mut n: u32) -> FixedString<16> {
    if n == 0 {
        let mut result = FixedString::new();
        let _ = result.push('0');
        return result;
    }

    let mut digits = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        digits[i] = (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    let mut result = FixedString::new();
    for j in (0..i).rev() {
        let _ = result.push((b'0' + digits[j]) as char);
    }

    result
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub cryptocurrency: Cryptocurrency,
    pub address: FixedString<128>,
    pub derivation_path: FixedString<64>,
    pub account_index: u32,
}

pub struct Wallet {
    pub mnemonic: FixedString<256>,
    pub seed: [u8; 64],
    pub master_key: MasterKey,
    pub accounts: Vec<AccountInfo>,
}

impl Wallet {
    pub fn create_new(entropy: &[u8], passphrase: &str) -> WalletResult<Self> {
        let mnemonic_type = match entropy.len() {
            16 => MnemonicType::Words12,
            20 => MnemonicType::Words15,
            24 => MnemonicType::Words18,
            28 => MnemonicType::Words21,
            32 => MnemonicType::Words24,
            _ => return Err(WalletError::InvalidEntropy),
        };

        let words =
            entropy_to_mnemonic(entropy, mnemonic_type).map_err(|_| WalletError::InvalidEntropy)?;

        let mut mnemonic_str = FixedString::new();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                mnemonic_str
                    .push_str(" ")
                    .map_err(|_| WalletError::AddressTooLong)?;
            }

            mnemonic_str
                .push_str(word)
                .map_err(|_| WalletError::AddressTooLong)?;
        }
        let seed = mnemonic_to_seed(mnemonic_str.as_str(), passphrase);
        let master_key = MasterKey::from_seed(&seed).map_err(|_| WalletError::InvalidSeed)?;

        Ok(Wallet {
            mnemonic: mnemonic_str,
            seed,
            master_key,
            accounts: Vec::new(),
        })
    }

    pub fn from_mnemonic(mnemonic_phrase: &str, passphrase: &str) -> WalletResult<Self> {
        let words: Vec<&str> = mnemonic_phrase.split_whitespace().collect();
        if !validate_mnemonic(&words) {
            return Err(WalletError::InvalidMnemonic);
        }

        let _entropy = mnemonic_to_entropy(&words).map_err(|_| WalletError::InvalidMnemonic)?;
        let seed = mnemonic_to_seed(mnemonic_phrase, passphrase);

        let master_key = MasterKey::from_seed(&seed).map_err(|_| WalletError::InvalidSeed)?;
        let mnemonic =
            FixedString::from_str(mnemonic_phrase).map_err(|_| WalletError::AddressTooLong)?;

        Ok(Wallet {
            mnemonic,
            seed,
            master_key,
            accounts: Vec::new(),
        })
    }

    /// 添加一个新账户（指定币种、账户索引和地址索引）
    pub fn add_account(
        &mut self,
        cryptocurrency: Cryptocurrency,
        account_index: u32,
        address_index: u32,
    ) -> WalletResult<()> {
        let coin_type = cryptocurrency.coin_type();

        // 检查账户是否已存在
        for account in &self.accounts {
            if account.cryptocurrency == cryptocurrency && account.account_index == address_index {
                return Ok(()); // 已存在，无需添加
            }
        }

        let secret_key = self
            .master_key
            .derive_bip44(coin_type, account_index, 0, address_index)
            .map_err(|_| WalletError::DerivationFailed)?;

        let public_key =
            PublicKey::from_secret_key(&secret_key).map_err(|_| WalletError::InvalidKey)?;

        let address_bytes = generate_address(&public_key, cryptocurrency)
            .map_err(|_| WalletError::AddressTooLong)?;

        let address_str =
            core::str::from_utf8(&address_bytes).map_err(|_| WalletError::AddressTooLong)?;

        let address =
            FixedString::from_str(address_str).map_err(|_| WalletError::AddressTooLong)?;

        // 构建派生路径字符串
        let mut derivation_path_str = FixedString::<64>::new();
        derivation_path_str
            .push_str("m/44'/")
            .map_err(|_| WalletError::AddressTooLong)?;

        let coin_type_str = u32_to_string(coin_type);
        derivation_path_str
            .push_str(coin_type_str.as_str())
            .map_err(|_| WalletError::AddressTooLong)?;

        derivation_path_str
            .push_str("/")
            .map_err(|_| WalletError::AddressTooLong)?;

        let account_str = u32_to_string(account_index);
        derivation_path_str
            .push_str(account_str.as_str())
            .map_err(|_| WalletError::AddressTooLong)?;

        derivation_path_str
            .push_str("'/0/")
            .map_err(|_| WalletError::AddressTooLong)?;

        let address_str = u32_to_string(address_index);
        derivation_path_str
            .push_str(address_str.as_str())
            .map_err(|_| WalletError::AddressTooLong)?;

        let derivation_path = derivation_path_str;

        let account = AccountInfo {
            cryptocurrency,
            address,
            derivation_path,
            account_index: address_index,
        };

        self.accounts.push(account);
        Ok(())
    }

    pub fn get_address(
        &self,
        cryptocurrency: Cryptocurrency,
        account_index: u32,
        address_index: u32,
    ) -> WalletResult<FixedString<128>> {
        if let Some(account) = self
            .accounts
            .iter()
            .find(|a| a.cryptocurrency == cryptocurrency && a.account_index == address_index)
        {
            return Ok(account.address);
        }

        let coin_type = cryptocurrency.coin_type();

        let secret_key = self
            .master_key
            .derive_bip44(coin_type, account_index, 0, address_index)
            .map_err(|_| WalletError::DerivationFailed)?;

        let public_key =
            PublicKey::from_secret_key(&secret_key).map_err(|_| WalletError::InvalidKey)?;

        let address_bytes = generate_address(&public_key, cryptocurrency)
            .map_err(|_| WalletError::AddressTooLong)?;

        let address_str =
            core::str::from_utf8(&address_bytes).map_err(|_| WalletError::AddressTooLong)?;

        FixedString::from_str(address_str).map_err(|_| WalletError::AddressTooLong)
    }

    pub fn get_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn get_account(&self, index: usize) -> WalletResult<&AccountInfo> {
        self.accounts
            .get(index)
            .ok_or(WalletError::IndexOutOfBounds)
    }

    pub fn clear_accounts(&mut self) {
        self.accounts.clear();
    }
}
