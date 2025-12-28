// Keccak-256 哈希上下文
pub struct Keccak256 {
    state: [u64; 25],
    buffer: [u8; 136],
    buffer_len: usize,
    finalized: bool,
}

impl Keccak256 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; 136],
            buffer_len: 0,
            finalized: false,
        }
    }

    /// 更新哈希状态
    pub fn update(&mut self, data: &[u8]) {
        if self.finalized {
            return;
        }

        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len == 136 {
                self.absorb();
                self.buffer_len = 0;
            }
        }
    }

    /// 完成哈希计算并返回结果
    pub fn finalize(mut self) -> [u8; 32] {
        if !self.finalized {
            // Padding (SHA-3/Keccak)
            self.buffer[self.buffer_len] = 0x06;
            self.buffer_len += 1;

            // 填充直到缓冲区满
            while self.buffer_len < 136 {
                self.buffer[self.buffer_len] = 0x00;
                self.buffer_len += 1;
            }

            // 最后一个字节设置最高位
            self.buffer[135] |= 0x80;

            self.absorb();
            self.finalized = true;
        }

        // 挤出 32 字节的哈希
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = ((self.state[i / 8] >> ((i % 8) * 8)) & 0xff) as u8;
        }
        result
    }

    /// 计算数据的 Keccak-256 哈希
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// 吸收阶段
    fn absorb(&mut self) {
        for i in 0..17 {
            // 将缓冲区的 8 个字节转换为 u64（小端序）
            let mut word = 0u64;
            for j in 0..8 {
                if i * 8 + j < self.buffer_len {
                    word |= (self.buffer[i * 8 + j] as u64) << (j * 8);
                }
            }

            self.state[i] ^= word;
        }

        self.keccak_f();
    }

    /// Keccak-f[1600] 排列函数
    fn keccak_f(&mut self) {
        const ROUNDS: usize = 24;
        const RC: [u64; 24] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x0000000080000001, 0x8000000080008081,
            0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
            0x0000000080000001, 0x000000008000008b, 0x000000008000008a,
            0x00000000000000ff, 0x800000008000008f, 0x8000000000008081,
            0x8000000080000001, 0x8000000080008008, 0x000000000000008a,
            0x0000000080008001, 0x8000000080008081, 0x8000000000000001,
            0x8000000080008009, 0x000000000000008a, 0x0000000000008009,
        ];

        for round in 0..ROUNDS {
            // θ 步骤
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.state[x] ^ self.state[5 + x] ^ self.state[10 + x] 
                     ^ self.state[15 + x] ^ self.state[20 + x];
            }

            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }

            for x in 0..5 {
                for y in 0..5 {
                    self.state[5 * y + x] ^= d[x];
                }
            }

            // ρ 和 π 步骤
            let mut b = [0u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    let rot = self.rotation_offset(x, y);
                    b[5 * y + ((x + 3 * y) % 5)] = self.state[5 * y + x].rotate_left(rot as u32);
                }
            }

            self.state = b;

            // χ 步骤
            for y in 0..5 {
                let mut t = [0u64; 5];
                for x in 0..5 {
                    t[x] = b[5 * y + x];
                }
                for x in 0..5 {
                    b[5 * y + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
                }
            }

            self.state = b;

            // ι 步骤
            self.state[0] ^= RC[round];
        }
    }

    /// 旋转偏移表
    fn rotation_offset(&self, x: usize, y: usize) -> usize {
        match (x, y) {
            (0, 0) => 0,   (1, 0) => 1,   (2, 0) => 62,  (3, 0) => 28,  (4, 0) => 27,
            (0, 1) => 36,  (1, 1) => 44,  (2, 1) => 6,   (3, 1) => 55,  (4, 1) => 20,
            (0, 2) => 3,   (1, 2) => 10,  (2, 2) => 43,  (3, 2) => 25,  (4, 2) => 39,
            (0, 3) => 41,  (1, 3) => 45,  (2, 3) => 15,  (3, 3) => 21,  (4, 3) => 8,
            (0, 4) => 18,  (1, 4) => 2,   (2, 4) => 61,  (3, 4) => 56,  (4, 4) => 14,
            _ => 0,
        }
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}
