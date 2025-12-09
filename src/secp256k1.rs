extern crate alloc;

use crate::sha256::Sha256;
use alloc::vec::Vec;

/// secp256k1 曲线参数 - 质数（p = 2^256 - 2^32 - 977）
const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// secp256k1 曲线参数 - 秩（曲线上的点数）
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// secp256k1 生成点 G 的 x 坐标
const GX: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x69, 0x24, 0xef, 0x7c, 0xae, 0x82,
    0x24, 0x6c, 0x61, 0x90, 0xe5, 0x38, 0x45, 0xb0,
    0xcf, 0x43, 0x19, 0xea, 0x1f, 0xa8, 0xf7, 0x24,
];

/// secp256k1 生成点 G 的 y 坐标
const GY: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

/// 模逆元计算（使用扩展欧几里得算法）
/// 计算 a^(-1) mod m
fn mod_inverse(a: &[u8; 32], m: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    // 检查 a 是否为零
    let mut is_zero = true;
    for &byte in a {
        if byte != 0 {
            is_zero = false;
            break;
        }
    }
    
    if is_zero {
        return Err("Cannot invert zero");
    }
    
    // 对于 secp256k1，使用费马小定理的近似：a^(-1) = a^(p-2) mod p
    // 这里使用二进制幂运算（从高位到低位）
    
    // p - 2 的二进制表示
    // p = 2^256 - 2^32 - 977，所以 p - 2 = 2^256 - 2^32 - 979
    let p_minus_2 = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2d,
    ];
    
    let mut result = [0u8; 32];
    result[31] = 1; // result = 1
    
    let base = *a;
    
    // 使用二进制幂运算计算 a^(p-2)
    // 从最高位到最低位遍历 p-2
    for &byte in &p_minus_2 {
        for bit in (0..8).rev() {
            // 平方
            result = mod_mul(&result, &result, m);
            
            // 如果当前位是 1，则乘以底数
            if (byte >> bit) & 1 == 1 {
                result = mod_mul(&result, &base, m);
            }
        }
    }
    
    // 验证结果（可选）
    let verification = mod_mul(&result, a, m);
    let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    
    if verification != one {
        return Err("Modular inverse calculation failed");
    }
    
    Ok(result)
}

/// 大整数模加
fn mod_add(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    
    // 如果溢出，减去 m
    if carry > 0 {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = result[i] as i16 - m[i] as i16 - borrow;
            result[i] = diff as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
    }
    
    result
}

/// 大整数模减
fn mod_sub(a: &[u8; 32], b: &[u8; 32], _m: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (256 + diff) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    
    result
}

/// 大整数模乘（使用长乘法和模约化）
fn mod_mul(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 64];
    
    // 长乘法
    for i in 0..32 {
        let mut carry = 0u16;
        for j in 0..32 {
            let mul = (a[i] as u16) * (b[j] as u16) + (result[i + j] as u16) + carry;
            result[i + j] = (mul & 0xff) as u8;
            carry = mul >> 8;
        }
        if i < 31 {
            result[i + 32] = (carry & 0xff) as u8;
        }
    }
    
    // 模约化（简化版本：对于 secp256k1 使用特殊约化）
    let mut reduced = [0u8; 32];
    reduced.copy_from_slice(&result[..32]);
    
    // 检查是否需要减去 m
    let mut need_sub = false;
    for i in 0..32 {
        if result[i] > reduced[i] {
            need_sub = true;
            break;
        } else if result[i] < reduced[i] {
            break;
        }
    }
    
    if need_sub {
        let _ = mod_sub(&reduced, m, m);
    }
    
    reduced
}

/// 椭圆曲线点（仿射坐标）
#[derive(Clone, Copy, Debug)]
struct ECPoint {
    x: [u8; 32],
    y: [u8; 32],
    is_infinity: bool,
}

impl ECPoint {
    /// 获得无穷远点
    fn infinity() -> Self {
        ECPoint {
            x: [0; 32],
            y: [0; 32],
            is_infinity: true,
        }
    }
    
    /// 点加法：P + Q
    fn add(&self, other: &ECPoint) -> Result<ECPoint, &'static str> {
        if self.is_infinity {
            return Ok(*other);
        }
        if other.is_infinity {
            return Ok(*self);
        }
        
        // 检查是否是点倍增
        let is_same_x = self.x == other.x;
        let is_same_y = self.y == other.y;
        
        if is_same_x && is_same_y {
            // 点倍增
            return self.double();
        }
        
        if is_same_x && !is_same_y {
            // P + (-P) = O（无穷远点）
            return Ok(ECPoint::infinity());
        }
        
        // 一般情况：(x1 != x2)
        // s = (y2 - y1) / (x2 - x1)
        // x3 = s^2 - x1 - x2
        // y3 = s * (x1 - x3) - y1
        
        let dx = mod_sub(&other.x, &self.x, &P);
        let dy = mod_sub(&other.y, &self.y, &P);
        
        let s = mod_mul(&dy, &mod_inverse(&dx, &P)?, &P);
        
        let s2 = mod_mul(&s, &s, &P);
        let x3 = mod_sub(&s2, &mod_add(&self.x, &other.x, &P), &P);
        let y3 = mod_sub(&mod_mul(&s, &mod_sub(&self.x, &x3, &P), &P), &self.y, &P);
        
        Ok(ECPoint {
            x: x3,
            y: y3,
            is_infinity: false,
        })
    }
    
    /// 点倍增：2P
    fn double(&self) -> Result<ECPoint, &'static str> {
        if self.is_infinity {
            return Ok(ECPoint::infinity());
        }
        
        // s = (3 * x1^2) / (2 * y1)
        // x3 = s^2 - 2 * x1
        // y3 = s * (x1 - x3) - y1
        
        let three = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        
        let x1_squared = mod_mul(&self.x, &self.x, &P);
        let three_x1_squared = mod_mul(&three, &x1_squared, &P);
        let two_y1 = mod_add(&self.y, &self.y, &P);
        
        let s = mod_mul(&three_x1_squared, &mod_inverse(&two_y1, &P)?, &P);
        let s_squared = mod_mul(&s, &s, &P);
        let two_x1 = mod_add(&self.x, &self.x, &P);
        
        let x3 = mod_sub(&s_squared, &two_x1, &P);
        let y3 = mod_sub(&mod_mul(&s, &mod_sub(&self.x, &x3, &P), &P), &self.y, &P);
        
        Ok(ECPoint {
            x: x3,
            y: y3,
            is_infinity: false,
        })
    }
    
    /// 标量乘法：k * P（使用二进制方法）
    fn scalar_mul(&self, scalar: &[u8; 32]) -> Result<ECPoint, &'static str> {
        let mut result = ECPoint::infinity();
        let mut temp = *self;
        
        // 从最低位到最高位遍历标量
        for &byte in scalar {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.add(&temp)?;
                }
                temp = temp.double()?;
            }
        }
        
        Ok(result)
    }
}

/// 私钥（32 字节）
#[derive(Clone, Copy)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// 从字节创建私钥（带验证）
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, &'static str> {
        // 检查私钥是否为零
        let mut is_zero = true;
        for &byte in bytes {
            if byte != 0 {
                is_zero = false;
                break;
            }
        }
        
        if is_zero {
            return Err("Private key cannot be zero");
        }
        
        // 检查私钥是否 >= N（秩）
        let mut is_ge_n = false;
        for i in 0..32 {
            if bytes[i] > N[i] {
                is_ge_n = true;
                break;
            } else if bytes[i] < N[i] {
                break;
            }
        }
        
        if is_ge_n {
            return Err("Private key is out of range (>= N)");
        }
        
        Ok(SecretKey(*bytes))
    }
    
    /// 从种子派生私钥
    pub fn from_seed(seed: &[u8]) -> Self {
        let hash = Sha256::digest(seed);
        SecretKey(hash)
    }
    
    /// 获取私钥字节
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 公钥（椭圆曲线点）
#[derive(Clone, Copy)]
pub struct PublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

impl PublicKey {
    /// 从私钥导出公钥
    /// 公钥 = 私钥 * G（G 是生成点）
    pub fn from_secret_key(secret_key: &SecretKey) -> Result<Self, &'static str> {
        let g = ECPoint {
            x: GX,
            y: GY,
            is_infinity: false,
        };
        
        let point = g.scalar_mul(secret_key.as_bytes())?;
        
        if point.is_infinity {
            return Err("Generated point is at infinity");
        }
        
        Ok(PublicKey {
            x: point.x,
            y: point.y,
        })
    }
    
    /// 获取 x 坐标
    pub fn x(&self) -> &[u8; 32] {
        &self.x
    }
    
    /// 获取 y 坐标
    pub fn y(&self) -> &[u8; 32] {
        &self.y
    }
    
    /// 压缩公钥格式（33 字节）：[前缀][x 坐标]
    /// 前缀：0x02（y 为偶数）或 0x03（y 为奇数）
    pub fn serialize_compressed(&self) -> [u8; 33] {
        let mut result = [0u8; 33];
        // 检查 y 的奇偶性
        let y_is_odd = (self.y[31] & 1) != 0;
        result[0] = if y_is_odd { 0x03 } else { 0x02 };
        result[1..].copy_from_slice(&self.x);
        result
    }
    
    /// 未压缩公钥格式（65 字节）：[0x04][x 坐标][y 坐标]
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[0] = 0x04;
        result[1..33].copy_from_slice(&self.x);
        result[33..65].copy_from_slice(&self.y);
        result
    }
    
    /// 返回公钥的压缩字节向量
    pub fn to_compressed_vec(&self) -> Vec<u8> {
        Vec::from(&self.serialize_compressed()[..])
    }
    
    /// 返回公钥的未压缩字节向量
    pub fn to_uncompressed_vec(&self) -> Vec<u8> {
        Vec::from(&self.serialize_uncompressed()[..])
    }
}

