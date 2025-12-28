use core::fmt;
use core::str::FromStr;

/// 固定大小的字符串
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixedString<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> FixedString<N> {
    /// 创建新的空字符串
    pub fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }

    /// 从字符串切片创建（如果长度超过容量则截断）
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        let bytes = s.as_bytes();
        if bytes.len() > N {
            return Err("String too long");
        }

        let mut data = [0u8; N];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }

    /// 从字节切片创建
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > N {
            return Err("Bytes too long");
        }

        let mut data = [0u8; N];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }

    /// 获取字符串切片
    pub fn as_str(&self) -> &str {
        // 安全：我们只存储有效的 UTF-8 字节
        unsafe { core::str::from_utf8_unchecked(&self.data[..self.len]) }
    }

    /// 获取字节切片
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// 获取长度
    pub fn len(&self) -> usize {
        self.len
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 清空字符串
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// 推入一个字符（如果空间足够）
    pub fn push(&mut self, ch: char) -> Result<(), &'static str> {
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        let encoded_len = encoded.len();

        if self.len + encoded_len > N {
            return Err("String too long");
        }

        self.data[self.len..self.len + encoded_len].copy_from_slice(encoded.as_bytes());
        self.len += encoded_len;
        Ok(())
    }

    /// 推入字符串（如果空间足够）
    pub fn push_str(&mut self, s: &str) -> Result<(), &'static str> {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err("String too long");
        }

        self.data[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

impl<const N: usize> Default for FixedString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Display for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<const N: usize> fmt::Debug for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

impl<const N: usize> FromStr for FixedString<N> {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

impl<const N: usize> AsRef<str> for FixedString<N> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

