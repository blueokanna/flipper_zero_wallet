pub struct Ripemd160 {
    state: [u32; 5],
    length: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Ripemd160 {
    /// 创建新的 RIPEMD-160 上下文
    pub fn new() -> Self {
        Self {
            state: [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476,
                0xc3d2e1f0,
            ],
            length: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    /// 更新哈希状态
    pub fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;

        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len == 64 {
                self.process_block();
                self.buffer_len = 0;
            }
        }
    }

    /// 完成哈希计算并返回结果
    pub fn finalize(mut self) -> [u8; 20] {
        // 添加填充
        let bit_len = self.length * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // 添加长度（小端序 64 位）
        for i in 0..8 {
            self.buffer[56 + i] = ((bit_len >> (i * 8)) & 0xff) as u8;
        }
        self.process_block();

        // 将状态转换为字节数组（小端序）
        let mut result = [0u8; 20];
        for i in 0..5 {
            let word = self.state[i];
            result[i * 4] = (word & 0xff) as u8;
            result[i * 4 + 1] = ((word >> 8) & 0xff) as u8;
            result[i * 4 + 2] = ((word >> 16) & 0xff) as u8;
            result[i * 4 + 3] = ((word >> 24) & 0xff) as u8;
        }
        result
    }

    /// 计算数据的 RIPEMD-160 哈希
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// 处理 64 字节的数据块
    fn process_block(&mut self) {
        // 将块转换为 16 个 32 位字（小端序）
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = (self.buffer[i * 4] as u32)
                | ((self.buffer[i * 4 + 1] as u32) << 8)
                | ((self.buffer[i * 4 + 2] as u32) << 16)
                | ((self.buffer[i * 4 + 3] as u32) << 24);
        }

        // 初始化工作变量
        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut el = self.state[4];

        let mut ar = self.state[0];
        let mut br = self.state[1];
        let mut cr = self.state[2];
        let mut dr = self.state[3];
        let mut er = self.state[4];

        // 左线
        for j in 0..80 {
            let (k, _rol_amount, _r_idx) = if j < 16 {
                (0x00000000, 0, 0)
            } else if j < 32 {
                (0x5a827999, 0, 1)
            } else if j < 48 {
                (0x6ed9eba1, 0, 2)
            } else if j < 64 {
                (0x8f1bbcdc, 0, 3)
            } else {
                (0xa953fd4e, 0, 4)
            };

            let f_val = if j < 16 {
                al ^ bl ^ cl
            } else if j < 32 {
                (al & bl) | (!al & cl)
            } else if j < 48 {
                (al | !bl) ^ cl
            } else if j < 64 {
                (al & cl) | (bl & !cl)
            } else {
                al ^ (bl | !cl)
            };

            let rol_amount = if j < 16 {
                [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8][j % 16]
            } else if j < 32 {
                [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 4][j % 16]
            } else if j < 48 {
                [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12][j % 16]
            } else if j < 64 {
                [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2][j % 16]
            } else {
                [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13][j % 16]
            };

            let r_idx = if j < 16 {
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15][j]
            } else if j < 32 {
                [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8][j % 16]
            } else if j < 48 {
                [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12][j % 16]
            } else if j < 64 {
                [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2][j % 16]
            } else {
                [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13][j % 16]
            };

            let t = al.wrapping_add(f_val)
                .wrapping_add(x[r_idx])
                .wrapping_add(k);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t.rotate_left(rol_amount);
        }

        // 右线
        for j in 0..80 {
            let f_val = if j < 16 {
                ar ^ (br | !cr)
            } else if j < 32 {
                (ar & cr) | (br & !cr)
            } else if j < 48 {
                (ar | !br) ^ cr
            } else if j < 64 {
                (ar & br) | (!ar & cr)
            } else {
                ar ^ br ^ cr
            };

            let k = if j < 16 {
                0x50a28be6
            } else if j < 32 {
                0x5c4dd124
            } else if j < 48 {
                0x6d703ef3
            } else if j < 64 {
                0x7a6d76e9
            } else {
                0x00000000
            };

            let rol_amount = if j < 16 {
                [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6][j % 16]
            } else if j < 32 {
                [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11][j % 16]
            } else if j < 48 {
                [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5][j % 16]
            } else if j < 64 {
                [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8][j % 16]
            } else {
                [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11][j % 16]
            };

            let r_idx = if j < 16 {
                [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12][j % 16]
            } else if j < 32 {
                [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2][j % 16]
            } else if j < 48 {
                [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13][j % 16]
            } else if j < 64 {
                [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14][j % 16]
            } else {
                [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11][j % 16]
            };

            let t = ar.wrapping_add(f_val)
                .wrapping_add(x[r_idx])
                .wrapping_add(k);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t.rotate_left(rol_amount);
        }

        // 更新状态
        let t = self.state[1].wrapping_add(cl).wrapping_add(dr);
        self.state[1] = self.state[2].wrapping_add(dl).wrapping_add(er);
        self.state[2] = self.state[3].wrapping_add(el).wrapping_add(ar);
        self.state[3] = self.state[4].wrapping_add(al).wrapping_add(br);
        self.state[4] = self.state[0].wrapping_add(bl).wrapping_add(cr);
        self.state[0] = t;
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self::new()
    }
}
