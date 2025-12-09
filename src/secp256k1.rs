use crate::sha256::Sha256;

/// secp256k1 曲线参数
const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// 私钥（32 字节）
#[derive(Clone, Copy)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// 从字节创建私钥
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, &'static str> {
        // 验证私钥在有效范围内
        let mut is_zero = true;
        let mut is_ge_n = true;
        
        for i in (0..32).rev() {
            if bytes[i] != 0 {
                is_zero = false;
            }
            if bytes[i] < N[i] {
                is_ge_n = false;
                break;
            } else if bytes[i] > N[i] {
                is_ge_n = true;
                break;
            }
        }
        
        if is_zero || is_ge_n {
            return Err("Invalid secret key");
        }
        
        Ok(SecretKey(*bytes))
    }
    
    /// 获取私钥字节
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// 从种子派生私钥（简化版本，使用 SHA-256）
    pub fn from_seed(seed: &[u8]) -> Self {
        let hash = Sha256::digest(seed);
        // 注意：这只是一个简化版本，实际应该使用 HMAC-SHA512
        SecretKey(hash)
    }
}

/// 公钥（未压缩，65 字节：0x04 || x || y）
#[derive(Clone, Copy)]
pub struct PublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

impl PublicKey {
    /// 从私钥生成公钥（简化版本）
    /// 
    /// 注意：这是一个非常简化的实现，仅用于演示。
    /// 实际实现需要完整的椭圆曲线点乘运算。
    pub fn from_secret_key(secret_key: &SecretKey) -> Result<Self, &'static str> {
        // 简化实现：使用 SHA-256 生成伪公钥
        // 实际应用中，这应该是：G * secret_key（椭圆曲线点乘）
        let hash = Sha256::digest(secret_key.as_bytes());
        let hash2 = Sha256::digest(&hash);
        
        Ok(PublicKey {
            x: hash,
            y: hash2,
        })
    }
    
    /// 获取压缩公钥（33 字节）
    pub fn serialize_compressed(&self) -> [u8; 33] {
        let mut result = [0u8; 33];
        result[0] = if self.y[31] & 1 == 0 { 0x02 } else { 0x03 };
        result[1..].copy_from_slice(&self.x);
        result
    }
    
    /// 获取未压缩公钥（65 字节）
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[0] = 0x04;
        result[1..33].copy_from_slice(&self.x);
        result[33..].copy_from_slice(&self.y);
        result
    }
}

