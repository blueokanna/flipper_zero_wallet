//! 钱包核心功能测试和使用示例
//! 
//! 本文件展示如何使用改进后的钱包库

#[cfg(test)]
mod tests {
    use flipper_zero_wallet::bip39::{entropy_to_mnemonic, MnemonicType};
    use flipper_zero_wallet::secp256k1::SecretKey;
    use flipper_zero_wallet::address::Cryptocurrency;
    
    #[test]
    fn test_secp256k1_key_generation() {
        // 测试 secp256k1 私钥和公钥生成
        
        // 创建一个有效的私钥（不为 0）
        let private_key_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // = 1
        ];
        
        // 从字节创建私钥
        let secret_key = SecretKey::from_bytes(&private_key_bytes);
        assert!(secret_key.is_ok());
        
        let secret_key = secret_key.unwrap();
        
        // 从私钥导出公钥
        let public_key = flipper_zero_wallet::secp256k1::PublicKey::from_secret_key(&secret_key);
        assert!(public_key.is_ok());
        
        // 获取公钥的压缩形式（33 字节）
        let public_key = public_key.unwrap();
        let compressed = public_key.serialize_compressed();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03); // 前缀检查
        
        // 获取公钥的未压缩形式（65 字节）
        let uncompressed = public_key.serialize_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // 未压缩前缀
    }
    
    #[test]
    fn test_mnemonic_generation() {
        // 测试 BIP39 助记词生成
        
        // 128 位熵（12 个词）
        let entropy_12 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        
        let mnemonic = entropy_to_mnemonic(&entropy_12, MnemonicType::Words12);
        assert!(mnemonic.is_ok());
        
        let words = mnemonic.unwrap();
        assert_eq!(words.len(), 12);
        
        // 256 位熵（24 个词）
        let entropy_24 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        
        let mnemonic = entropy_to_mnemonic(&entropy_24, MnemonicType::Words24);
        assert!(mnemonic.is_ok());
        
        let words = mnemonic.unwrap();
        assert_eq!(words.len(), 24);
    }
    
    #[test]
    fn test_bip32_derivation() {
        // 测试 BIP32 派生路径
        
        // 创建一个测试种子（64 字节）
        let seed = [0x00u8; 64];
        
        let master_key = flipper_zero_wallet::bip32::MasterKey::from_seed(&seed);
        assert!(master_key.is_ok());
        
        let master_key = master_key.unwrap();
        
        // 派生 BIP44 路径：m/44'/0'/0'/0/0（Bitcoin 第一个地址）
        let address_key = master_key.derive_bip44(0, 0, 0, 0);
        assert!(address_key.is_ok());
        
        // 派生 BIP44 路径：m/44'/60'/0'/0/0（Ethereum 第一个地址）
        let address_key = master_key.derive_bip44(60, 0, 0, 0);
        assert!(address_key.is_ok());
    }
    
    #[test]
    fn test_address_generation() {
        // 测试地址生成
        
        // 这需要完整的钱包上下文，参考 flipper_wallet_core.rs
        // 通常在钱包初始化后执行
    }
}

/// 用法示例
///
/// 1. 创建新钱包：
/// ```ignore
/// let entropy = [0x00u8; 16]; // 128 位随机熵
/// let wallet = Wallet::create_new(&entropy, "")?;
/// println!("助记词: {}", wallet.get_mnemonic());
/// ```
///
/// 2. 从助记词恢复钱包：
/// ```ignore
/// let mnemonic = "abandon abandon abandon ... (24 个词)";
/// let wallet = Wallet::from_mnemonic(mnemonic, "")?;
/// ```
///
/// 3. 添加账户：
/// ```ignore
/// wallet.add_account(Cryptocurrency::Bitcoin, 0, 0)?;
/// wallet.add_account(Cryptocurrency::Ethereum, 0, 0)?;
/// ```
///
/// 4. 查看账户信息：
/// ```ignore
/// for i in 0..wallet.account_count() {
///     let account = wallet.get_account(i)?;
///     println!("币种: {}", account.cryptocurrency.display_name());
///     println!("地址: {}", account.address.as_str());
///     println!("路径: {}", account.derivation_path.as_str());
/// }
/// ```

// 模块结构
// src/
// ├── secp256k1.rs          - 椭圆曲线加密（已完善）
// ├── bip32.rs              - BIP32 分层确定性派生（已完善）
// ├── bip39.rs              - BIP39 助记词
// ├── pbkdf2.rs             - PBKDF2 密钥派生
// ├── sha256.rs             - SHA-256 哈希
// ├── address.rs            - 地址生成
// ├── flipper_wallet_core.rs - 钱包核心逻辑（已完善）
// ├── fixed_string.rs       - 固定大小字符串（no_std）
// ├── hex.rs                - 十六进制编码/解码
// └── word_list.rs          - BIP39 词表
