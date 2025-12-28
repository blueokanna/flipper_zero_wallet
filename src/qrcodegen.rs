/*
QR Code Generator Library (Rust)

Based on the QR Code Generator Library by Project Nayuki.(MIT License)
https://www.nayuki.io/page/qr-code-generator-library

Modified for Flipper Zero environment by Blueokanna.
*/
#![allow(dead_code)]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;

#[derive(Clone, PartialEq, Eq)]
pub struct QrCode {
    version: Version,
    size: i32,
    errorcorrectionlevel: QrCodeEcc,
    mask: Mask,
    modules: Vec<bool>,
    isfunction: Vec<bool>,
}

impl QrCode {
    pub fn encode_text(text: &str, ecl: QrCodeEcc) -> Result<Self, DataTooLong> {
        let segs: Vec<QrSegment> = QrSegment::make_segments(text);
        QrCode::encode_segments(&segs, ecl)
    }

    pub fn encode_binary(data: &[u8], ecl: QrCodeEcc) -> Result<Self, DataTooLong> {
        let segs: [QrSegment; 1] = [QrSegment::make_bytes(data)];
        QrCode::encode_segments(&segs, ecl)
    }

    pub fn encode_segments(segs: &[QrSegment], ecl: QrCodeEcc) -> Result<Self, DataTooLong> {
        QrCode::encode_segments_advanced(segs, ecl, Version::MIN, Version::MAX, None, true)
    }

    pub fn encode_segments_advanced(
        segs: &[QrSegment],
        mut ecl: QrCodeEcc,
        minversion: Version,
        maxversion: Version,
        mask: Option<Mask>,
        boostecl: bool,
    ) -> Result<Self, DataTooLong> {
        assert!(minversion <= maxversion, "Invalid value");

        // Find the minimal version number to use
        let mut version: Version = minversion;
        let datausedbits: usize = loop {
            let datacapacitybits: usize = QrCode::get_num_data_codewords(version, ecl) * 8;
            let dataused: Option<usize> = QrSegment::get_total_bits(segs, version);
            if dataused.map_or(false, |n| n <= datacapacitybits) {
                break dataused.unwrap();
            } else if version >= maxversion {
                return Err(match dataused {
                    None => DataTooLong::SegmentTooLong,
                    Some(n) => DataTooLong::DataOverCapacity(n, datacapacitybits),
                });
            } else {
                version = Version::new(version.value() + 1);
            }
        };

        for &newecl in &[QrCodeEcc::Medium, QrCodeEcc::Quartile, QrCodeEcc::High] {
            if boostecl && datausedbits <= QrCode::get_num_data_codewords(version, newecl) * 8 {
                ecl = newecl;
            }
        }

        // Concatenate all segments to create the data bit string
        let mut bb = BitBuffer(Vec::new());
        for seg in segs {
            bb.append_bits(seg.mode.mode_bits(), 4);
            bb.append_bits(
                u32::try_from(seg.numchars).unwrap(),
                seg.mode.num_char_count_bits(version),
            );
            bb.0.extend_from_slice(&seg.data);
        }
        debug_assert_eq!(bb.0.len(), datausedbits);

        let datacapacitybits: usize = QrCode::get_num_data_codewords(version, ecl) * 8;
        debug_assert!(bb.0.len() <= datacapacitybits);
        let numzerobits: usize = core::cmp::min(4, datacapacitybits - bb.0.len());
        bb.append_bits(0, u8::try_from(numzerobits).unwrap());
        let numzerobits: usize = bb.0.len().wrapping_neg() & 7;
        bb.append_bits(0, u8::try_from(numzerobits).unwrap());
        debug_assert_eq!(bb.0.len() % 8, 0);

        for &padbyte in [0xEC, 0x11].iter().cycle() {
            if bb.0.len() >= datacapacitybits {
                break;
            }
            bb.append_bits(padbyte, 8);
        }

        let mut datacodewords = Vec::from(vec![0u8; bb.0.len() / 8]);
        for (i, &bit) in bb.0.iter().enumerate() {
            datacodewords[i >> 3] |= u8::from(bit) << (7 - (i & 7));
        }

        Ok(QrCode::encode_codewords(version, ecl, &datacodewords, mask))
    }

    pub fn encode_codewords(
        ver: Version,
        ecl: QrCodeEcc,
        datacodewords: &[u8],
        mut msk: Option<Mask>,
    ) -> Self {
        let size = usize::from(ver.value()) * 4 + 17;
        let mut result = Self {
            version: ver,
            size: size as i32,
            mask: Mask::new(0),
            errorcorrectionlevel: ecl,
            modules: Vec::from(vec![false; size * size]),
            isfunction: Vec::from(vec![false; size * size]),
        };

        // Compute ECC, draw modules
        result.draw_function_patterns();
        let allcodewords: Vec<u8> = result.add_ecc_and_interleave(datacodewords);
        result.draw_codewords(&allcodewords);

        // Do masking
        if msk.is_none() {
            // Automatically choose best mask
            let mut minpenalty = i32::MAX;
            for i in 0u8..8 {
                let i = Mask::new(i);
                result.apply_mask(i);
                result.draw_format_bits(i);
                let penalty: i32 = result.get_penalty_score();
                if penalty < minpenalty {
                    msk = Some(i);
                    minpenalty = penalty;
                }
                result.apply_mask(i);
            }
        }
        let msk: Mask = msk.unwrap();
        result.mask = msk;
        result.apply_mask(msk);
        result.draw_format_bits(msk);

        result.isfunction.clear();
        result.isfunction.shrink_to_fit();
        result
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn size(&self) -> i32 {
        self.size
    }

    pub fn error_correction_level(&self) -> QrCodeEcc {
        self.errorcorrectionlevel
    }

    pub fn mask(&self) -> Mask {
        self.mask
    }

    pub fn get_module(&self, x: i32, y: i32) -> bool {
        (0..self.size).contains(&x) && (0..self.size).contains(&y) && self.module(x, y)
    }

    fn module(&self, x: i32, y: i32) -> bool {
        self.modules[(y * self.size + x) as usize]
    }

    fn module_mut(&mut self, x: i32, y: i32) -> &mut bool {
        &mut self.modules[(y * self.size + x) as usize]
    }

    fn draw_function_patterns(&mut self) {
        let size: i32 = self.size;
        for i in 0..size {
            self.set_function_module(6, i, i % 2 == 0);
            self.set_function_module(i, 6, i % 2 == 0);
        }

        self.draw_finder_pattern(3, 3);
        self.draw_finder_pattern(size - 4, 3);
        self.draw_finder_pattern(3, size - 4);

        let alignpatpos: Vec<i32> = self.get_alignment_pattern_positions();
        let numalign: usize = alignpatpos.len();
        for i in 0..numalign {
            for j in 0..numalign {
                // Don't draw on the three finder corners
                if !(i == 0 && j == 0 || i == 0 && j == numalign - 1 || i == numalign - 1 && j == 0)
                {
                    self.draw_alignment_pattern(alignpatpos[i], alignpatpos[j]);
                }
            }
        }

        self.draw_format_bits(Mask::new(0));
        self.draw_version();
    }

    fn draw_format_bits(&mut self, mask: Mask) {
        let bits: u32 = {
            let data: u32 = u32::from(self.errorcorrectionlevel.format_bits() << 3 | mask.value());
            let mut rem: u32 = data;
            for _ in 0..10 {
                rem = (rem << 1) ^ ((rem >> 9) * 0x537);
            }
            (data << 10 | rem) ^ 0x5412 // uint15
        };
        debug_assert_eq!(bits >> 15, 0);

        for i in 0..6 {
            self.set_function_module(8, i, get_bit(bits, i));
        }
        self.set_function_module(8, 7, get_bit(bits, 6));
        self.set_function_module(8, 8, get_bit(bits, 7));
        self.set_function_module(7, 8, get_bit(bits, 8));
        for i in 9..15 {
            self.set_function_module(14 - i, 8, get_bit(bits, i));
        }

        // Draw second copy
        let size: i32 = self.size;
        for i in 0..8 {
            self.set_function_module(size - 1 - i, 8, get_bit(bits, i));
        }
        for i in 8..15 {
            self.set_function_module(8, size - 15 + i, get_bit(bits, i));
        }
        self.set_function_module(8, size - 8, true); // Always dark
    }

    fn draw_version(&mut self) {
        if self.version.value() < 7 {
            return;
        }

        let bits: u32 = {
            let data = u32::from(self.version.value());
            let mut rem: u32 = data;
            for _ in 0..12 {
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
            }
            data << 12 | rem // uint18
        };
        debug_assert_eq!(bits >> 18, 0);

        // Draw two copies
        for i in 0..18 {
            let bit: bool = get_bit(bits, i);
            let a: i32 = self.size - 11 + i % 3;
            let b: i32 = i / 3;
            self.set_function_module(a, b, bit);
            self.set_function_module(b, a, bit);
        }
    }

    fn draw_finder_pattern(&mut self, x: i32, y: i32) {
        for dy in -4..=4 {
            for dx in -4..=4 {
                let xx: i32 = x + dx;
                let yy: i32 = y + dy;
                if (0..self.size).contains(&xx) && (0..self.size).contains(&yy) {
                    let dist: i32 = core::cmp::max(dx.abs(), dy.abs());
                    self.set_function_module(xx, yy, dist != 2 && dist != 4);
                }
            }
        }
    }

    fn draw_alignment_pattern(&mut self, x: i32, y: i32) {
        for dy in -2..=2 {
            for dx in -2..=2 {
                self.set_function_module(x + dx, y + dy, core::cmp::max(dx.abs(), dy.abs()) != 1);
            }
        }
    }

    fn set_function_module(&mut self, x: i32, y: i32, isdark: bool) {
        *self.module_mut(x, y) = isdark;
        self.isfunction[(y * self.size + x) as usize] = true;
    }

    fn add_ecc_and_interleave(&self, data: &[u8]) -> Vec<u8> {
        let ver: Version = self.version;
        let ecl: QrCodeEcc = self.errorcorrectionlevel;
        assert_eq!(
            data.len(),
            QrCode::get_num_data_codewords(ver, ecl),
            "Illegal argument"
        );

        // Calculate parameter numbers
        let numblocks: usize = QrCode::table_get(&NUM_ERROR_CORRECTION_BLOCKS, ver, ecl);
        let blockecclen: usize = QrCode::table_get(&ECC_CODEWORDS_PER_BLOCK, ver, ecl);
        let rawcodewords: usize = QrCode::get_num_raw_data_modules(ver) / 8;
        let numshortblocks: usize = numblocks - rawcodewords % numblocks;
        let shortblocklen: usize = rawcodewords / numblocks;

        // Split data into blocks and append ECC to each block
        let mut blocks = Vec::<Vec<u8>>::with_capacity(numblocks);
        let rsdiv: Vec<u8> = QrCode::reed_solomon_compute_divisor(blockecclen);
        let mut k: usize = 0;
        for i in 0..numblocks {
            let datlen: usize = shortblocklen - blockecclen + usize::from(i >= numshortblocks);
            let mut dat = data[k..k + datlen].to_vec();
            k += datlen;
            let ecc: Vec<u8> = QrCode::reed_solomon_compute_remainder(&dat, &rsdiv);
            if i < numshortblocks {
                dat.push(0);
            }
            dat.extend_from_slice(&ecc);
            blocks.push(dat);
        }

        // Interleave (not concatenate) the bytes from every block into a single sequence
        let mut result = Vec::<u8>::with_capacity(rawcodewords);
        for i in 0..=shortblocklen {
            for (j, block) in blocks.iter().enumerate() {
                // Skip the padding byte in short blocks
                if i != shortblocklen - blockecclen || j >= numshortblocks {
                    result.push(block[i]);
                }
            }
        }
        result
    }

    fn draw_codewords(&mut self, data: &[u8]) {
        assert_eq!(
            data.len(),
            QrCode::get_num_raw_data_modules(self.version) / 8,
            "Illegal argument"
        );

        let mut i: usize = 0; // Bit index into the data
                              // Do the funny zigzag scan
        let mut right: i32 = self.size - 1;
        while right >= 1 {
            // Index of right column in each column pair
            if right == 6 {
                right = 5;
            }
            for vert in 0..self.size {
                // Vertical counter
                for j in 0..2 {
                    let x: i32 = right - j; // Actual x coordinate
                    let upward: bool = (right + 1) & 2 == 0;
                    let y: i32 = if upward { self.size - 1 - vert } else { vert }; // Actual y coordinate
                    if !self.isfunction[(y * self.size + x) as usize] && i < data.len() * 8 {
                        *self.module_mut(x, y) =
                            get_bit(u32::from(data[i >> 3]), 7 - ((i as i32) & 7));
                        i += 1;
                    }
                }
            }
            right -= 2;
        }
        debug_assert_eq!(i, data.len() * 8);
    }

    fn apply_mask(&mut self, mask: Mask) {
        for y in 0..self.size {
            for x in 0..self.size {
                let invert: bool = match mask.value() {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    7 => ((x + y) % 2 + x * y % 3) % 2 == 0,
                    _ => unreachable!(),
                };
                *self.module_mut(x, y) ^= invert & !self.isfunction[(y * self.size + x) as usize];
            }
        }
    }

    fn get_penalty_score(&self) -> i32 {
        let mut result: i32 = 0;
        let size: i32 = self.size;

        // Adjacent modules in row having same color, and finder-like patterns
        for y in 0..size {
            let mut runcolor = false;
            let mut runx: i32 = 0;
            let mut runhistory = FinderPenalty::new(size);
            for x in 0..size {
                if self.module(x, y) == runcolor {
                    runx += 1;
                    if runx == 5 {
                        result += PENALTY_N1;
                    } else if runx > 5 {
                        result += 1;
                    }
                } else {
                    runhistory.add_history(runx);
                    if !runcolor {
                        result += runhistory.count_patterns() * PENALTY_N3;
                    }
                    runcolor = self.module(x, y);
                    runx = 1;
                }
            }
            result += runhistory.terminate_and_count(runcolor, runx) * PENALTY_N3;
        }
        // Adjacent modules in column having same color, and finder-like patterns
        for x in 0..size {
            let mut runcolor = false;
            let mut runy: i32 = 0;
            let mut runhistory = FinderPenalty::new(size);
            for y in 0..size {
                if self.module(x, y) == runcolor {
                    runy += 1;
                    if runy == 5 {
                        result += PENALTY_N1;
                    } else if runy > 5 {
                        result += 1;
                    }
                } else {
                    runhistory.add_history(runy);
                    if !runcolor {
                        result += runhistory.count_patterns() * PENALTY_N3;
                    }
                    runcolor = self.module(x, y);
                    runy = 1;
                }
            }
            result += runhistory.terminate_and_count(runcolor, runy) * PENALTY_N3;
        }

        // 2*2 blocks of modules having same color
        for y in 0..size - 1 {
            for x in 0..size - 1 {
                let color: bool = self.module(x, y);
                if color == self.module(x + 1, y)
                    && color == self.module(x, y + 1)
                    && color == self.module(x + 1, y + 1)
                {
                    result += PENALTY_N2;
                }
            }
        }

        // Balance of dark and light modules
        let dark: i32 = self.modules.iter().copied().map(i32::from).sum();
        let total: i32 = size * size; // Note that size is odd, so dark/total != 1/2
        let k: i32 = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
        debug_assert!(0 <= k && k <= 9);
        result += k * PENALTY_N4;
        debug_assert!(0 <= result && result <= 2568888);
        result
    }

    fn get_alignment_pattern_positions(&self) -> Vec<i32> {
        let ver: u8 = self.version.value();
        if ver == 1 {
            vec![]
        } else {
            let numalign = i32::from(ver) / 7 + 2;
            let step: i32 = if ver == 32 {
                26
            } else {
                (i32::from(ver) * 4 + numalign * 2 + 1) / (numalign * 2 - 2) * 2
            };
            let mut result: Vec<i32> = (0..numalign - 1)
                .map(|i| self.size - 7 - i * step)
                .collect();
            result.push(6);
            result.reverse();
            result
        }
    }

    fn get_num_raw_data_modules(ver: Version) -> usize {
        let ver = usize::from(ver.value());
        let mut result: usize = (16 * ver + 128) * ver + 64;
        if ver >= 2 {
            let numalign: usize = ver / 7 + 2;
            result -= (25 * numalign - 10) * numalign - 55;
            if ver >= 7 {
                result -= 36;
            }
        }
        debug_assert!((208..=29648).contains(&result));
        result
    }

    fn get_num_data_codewords(ver: Version, ecl: QrCodeEcc) -> usize {
        QrCode::get_num_raw_data_modules(ver) / 8
            - QrCode::table_get(&ECC_CODEWORDS_PER_BLOCK, ver, ecl)
                * QrCode::table_get(&NUM_ERROR_CORRECTION_BLOCKS, ver, ecl)
    }

    // Returns an entry from the given table based on the given values.
    fn table_get(table: &'static [[i8; 41]; 4], ver: Version, ecl: QrCodeEcc) -> usize {
        table[ecl.ordinal()][usize::from(ver.value())] as usize
    }

    fn reed_solomon_compute_divisor(degree: usize) -> Vec<u8> {
        assert!((1..=255).contains(&degree), "Degree out of range");

        let mut result = vec![0u8; degree - 1];
        result.push(1); // Start off with the monomial x^0

        let mut root: u8 = 1;
        for _ in 0..degree {
            for j in 0..degree {
                result[j] = QrCode::reed_solomon_multiply(result[j], root);
                if j + 1 < result.len() {
                    result[j] ^= result[j + 1];
                }
            }
            root = QrCode::reed_solomon_multiply(root, 0x02);
        }
        result
    }

    // Returns the Reed-Solomon error correction codeword for the given data and divisor polynomials.
    fn reed_solomon_compute_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; divisor.len()];
        for b in data {
            // Polynomial division
            let factor: u8 = b ^ result.remove(0);
            result.push(0);
            for (x, &y) in result.iter_mut().zip(divisor.iter()) {
                *x ^= QrCode::reed_solomon_multiply(y, factor);
            }
        }
        result
    }

    fn reed_solomon_multiply(x: u8, y: u8) -> u8 {
        let mut z: u8 = 0;
        for i in (0..8).rev() {
            z = (z << 1) ^ ((z >> 7) * 0x1D);
            z ^= ((y >> i) & 1) * x;
        }
        z
    }
}

struct FinderPenalty {
    qr_size: i32,
    run_history: [i32; 7],
}

impl FinderPenalty {
    pub fn new(size: i32) -> Self {
        Self {
            qr_size: size,
            run_history: [0i32; 7],
        }
    }

    pub fn add_history(&mut self, mut currentrunlength: i32) {
        if self.run_history[0] == 0 {
            currentrunlength += self.qr_size;
        }
        let rh = &mut self.run_history;
        for i in (0..rh.len() - 1).rev() {
            rh[i + 1] = rh[i];
        }
        rh[0] = currentrunlength;
    }

    pub fn count_patterns(&self) -> i32 {
        let rh = &self.run_history;
        let n = rh[1];
        debug_assert!(n <= self.qr_size * 3);
        let core = n > 0 && rh[2] == n && rh[3] == n * 3 && rh[4] == n && rh[5] == n;
        i32::from(core && rh[0] >= n * 4 && rh[6] >= n)
            + i32::from(core && rh[6] >= n * 4 && rh[0] >= n)
    }

    // Must be called at the end of a line (row or column) of modules.
    pub fn terminate_and_count(mut self, currentruncolor: bool, mut currentrunlength: i32) -> i32 {
        if currentruncolor {
            // Terminate dark run
            self.add_history(currentrunlength);
            currentrunlength = 0;
        }
        currentrunlength += self.qr_size;
        self.add_history(currentrunlength);
        self.count_patterns()
    }
}

const PENALTY_N1: i32 = 3;
const PENALTY_N2: i32 = 3;
const PENALTY_N3: i32 = 40;
const PENALTY_N4: i32 = 10;

static ECC_CODEWORDS_PER_BLOCK: [[i8; 41]; 4] = [
    [
        -1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ], // Low
    [
        -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ], // Medium
    [
        -1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30,
        30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ], // Quartile
    [
        -1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ], // High
];

static NUM_ERROR_CORRECTION_BLOCKS: [[i8; 41]; 4] = [
    [
        -1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12,
        13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ], // Low
    [
        -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ], // Medium
    [
        -1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27,
        29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ], // Quartile
    [
        -1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32,
        35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ], // High
];

/// The error correction level in a QR Code symbol.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum QrCodeEcc {
    Low,
    Medium,
    Quartile,
    High,
}

impl QrCodeEcc {
    fn ordinal(self) -> usize {
        use QrCodeEcc::*;
        match self {
            Low => 0,
            Medium => 1,
            Quartile => 2,
            High => 3,
        }
    }

    fn format_bits(self) -> u8 {
        use QrCodeEcc::*;
        match self {
            Low => 1,
            Medium => 0,
            Quartile => 3,
            High => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct QrSegment {
    mode: QrSegmentMode,
    numchars: usize,
    data: Vec<bool>,
}

impl QrSegment {
    pub fn make_bytes(data: &[u8]) -> Self {
        let mut bb = BitBuffer(Vec::with_capacity(data.len() * 8));
        for &b in data {
            bb.append_bits(u32::from(b), 8);
        }
        QrSegment::new(QrSegmentMode::Byte, data.len(), bb.0)
    }

    pub fn make_numeric(text: &str) -> Self {
        let mut bb = BitBuffer(Vec::with_capacity(text.len() * 3 + (text.len() + 2) / 3));
        let mut accumdata: u32 = 0;
        let mut accumcount: u8 = 0;
        for b in text.bytes() {
            assert!(
                (b'0'..=b'9').contains(&b),
                "String contains non-numeric characters"
            );
            accumdata = accumdata * 10 + u32::from(b - b'0');
            accumcount += 1;
            if accumcount == 3 {
                bb.append_bits(accumdata, 10);
                accumdata = 0;
                accumcount = 0;
            }
        }
        if accumcount > 0 {
            bb.append_bits(accumdata, accumcount * 3 + 1);
        }
        QrSegment::new(QrSegmentMode::Numeric, text.len(), bb.0)
    }

    pub fn make_alphanumeric(text: &str) -> Self {
        let mut bb = BitBuffer(Vec::with_capacity(text.len() * 5 + (text.len() + 1) / 2));
        let mut accumdata: u32 = 0;
        let mut accumcount: u32 = 0;
        for c in text.chars() {
            let i: usize = ALPHANUMERIC_CHARSET
                .find(c)
                .expect("String contains unencodable characters in alphanumeric mode");
            accumdata = accumdata * 45 + u32::try_from(i).unwrap();
            accumcount += 1;
            if accumcount == 2 {
                bb.append_bits(accumdata, 11);
                accumdata = 0;
                accumcount = 0;
            }
        }
        if accumcount > 0 {
            // 1 character remaining
            bb.append_bits(accumdata, 6);
        }
        QrSegment::new(QrSegmentMode::Alphanumeric, text.len(), bb.0)
    }

    pub fn make_segments(text: &str) -> Vec<Self> {
        if text.is_empty() {
            vec![]
        } else {
            vec![if QrSegment::is_numeric(text) {
                QrSegment::make_numeric(text)
            } else if QrSegment::is_alphanumeric(text) {
                QrSegment::make_alphanumeric(text)
            } else {
                QrSegment::make_bytes(text.as_bytes())
            }]
        }
    }

    pub fn make_eci(assignval: u32) -> Self {
        let mut bb = BitBuffer(Vec::with_capacity(24));
        if assignval < (1 << 7) {
            bb.append_bits(assignval, 8);
        } else if assignval < (1 << 14) {
            bb.append_bits(0b10, 2);
            bb.append_bits(assignval, 14);
        } else if assignval < 1_000_000 {
            bb.append_bits(0b110, 3);
            bb.append_bits(assignval, 21);
        } else {
            panic!("ECI assignment value out of range");
        }
        QrSegment::new(QrSegmentMode::Eci, 0, bb.0)
    }

    pub fn new(mode: QrSegmentMode, numchars: usize, data: Vec<bool>) -> Self {
        Self {
            mode,
            numchars,
            data,
        }
    }

    pub fn mode(&self) -> QrSegmentMode {
        self.mode
    }

    pub fn num_chars(&self) -> usize {
        self.numchars
    }

    pub fn data(&self) -> &Vec<bool> {
        &self.data
    }

    fn get_total_bits(segs: &[Self], version: Version) -> Option<usize> {
        let mut result: usize = 0;
        for seg in segs {
            let ccbits: u8 = seg.mode.num_char_count_bits(version);
            if let Some(limit) = 1usize.checked_shl(ccbits.into()) {
                if seg.numchars >= limit {
                    return None;
                }
            }
            result = result.checked_add(4 + usize::from(ccbits))?;
            result = result.checked_add(seg.data.len())?;
        }
        Some(result)
    }

    pub fn is_numeric(text: &str) -> bool {
        text.chars().all(|c| ('0'..='9').contains(&c))
    }

    pub fn is_alphanumeric(text: &str) -> bool {
        text.chars().all(|c| ALPHANUMERIC_CHARSET.contains(c))
    }
}

static ALPHANUMERIC_CHARSET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QrSegmentMode {
    Numeric,
    Alphanumeric,
    Byte,
    Kanji,
    Eci,
}

impl QrSegmentMode {
    fn mode_bits(self) -> u32 {
        use QrSegmentMode::*;
        match self {
            Numeric => 0x1,
            Alphanumeric => 0x2,
            Byte => 0x4,
            Kanji => 0x8,
            Eci => 0x7,
        }
    }

    fn num_char_count_bits(self, ver: Version) -> u8 {
        use QrSegmentMode::*;
        (match self {
            Numeric => [10, 12, 14],
            Alphanumeric => [9, 11, 13],
            Byte => [8, 16, 16],
            Kanji => [8, 10, 12],
            Eci => [0, 0, 0],
        })[usize::from((ver.value() + 7) / 17)]
    }
}

pub struct BitBuffer(pub Vec<bool>);

impl BitBuffer {
    pub fn append_bits(&mut self, val: u32, len: u8) {
        assert!(len <= 31 && val >> len == 0, "Value out of range");
        self.0
            .extend((0..i32::from(len)).rev().map(|i| get_bit(val, i))); // Append bit by bit
    }
}

#[derive(Debug, Clone)]
pub enum DataTooLong {
    SegmentTooLong,
    DataOverCapacity(usize, usize),
}

impl core::fmt::Display for DataTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Self::SegmentTooLong => write!(f, "Segment too long"),
            Self::DataOverCapacity(datalen, maxcapacity) => write!(
                f,
                "Data length = {} bits, Max capacity = {} bits",
                datalen, maxcapacity
            ),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version(u8);

impl Version {
    pub const MIN: Version = Version(1);
    pub const MAX: Version = Version(40);
    pub fn new(ver: u8) -> Self {
        assert!(
            (Version::MIN.value()..=Version::MAX.value()).contains(&ver),
            "Version number out of range"
        );
        Self(ver)
    }

    /// Returns the value, which is in the range [1, 40].
    pub fn value(self) -> u8 {
        self.0
    }
}

/// A number between 0 and 7 (inclusive).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Mask(u8);

impl Mask {
    pub fn new(mask: u8) -> Self {
        assert!(mask <= 7, "Mask value out of range");
        Self(mask)
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

fn get_bit(x: u32, i: i32) -> bool {
    (x >> i) & 1 != 0
}
