// todo: key input
// todo: interactive mode (CLI)
// todo: error handling
// todo: optimization
// todo: padding methods
// todo: _ecb_, cbc, cbf
// todo: multithreading
// todo: implement u256?..

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gost_sample() {
        // Encrypt-Decrypt
        let mut path_in: String = String::from(r"C:\OneDrive\Projects\Rust\libmagma\GOST_data.hex");
        let key_in = r"C:\OneDrive\Projects\Rust\libmagma\GOST_key.hex";

        // Key: ffeeddccbbaa9988776655443322113ff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        let hex_key: Vec<u8> = vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                                    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
                                    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
        let key = read_file_to_vec(key_in).unwrap();
        assert_eq!(key, hex_key);
        println!("Key:\n{:02x?}", key);
        
        // Data: fedcba9876543210
        let hex_data: Vec<u8> = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let mut data = read_file_to_vec(&path_in).unwrap();
        assert_eq!(hex_data, data);
        println!("Raw: {:02x?}", data);
        
        // Encrypted data: 4ee901e5c2d8ca3d
        let hex_enc_data: Vec<u8> = vec![0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d];
        encrypt_ecb(&path_in, &key);
        path_in.push_str(".enc");
        data = read_file_to_vec(&path_in).unwrap();
        // ISO/IEC 9797-1 Padding method 2 (added block removal)
        data.truncate(8);
        assert_eq!(hex_enc_data, data);
        println!("Enc: {:02x?}", data);

        // Decrypted data == Data
        decrypt_ecb(&path_in, &key);
        path_in = path_in.replace(".enc", ".dec");
        data = read_file_to_vec(&path_in).unwrap();
        assert_eq!(hex_data, data);
        println!("Dec: {:02x?}", data);
    }
}

use core::slice::{Iter, IterMut};
use std::{
    error::Error,
    fmt::{self, Display, Formatter, LowerHex},
    fs::{write, OpenOptions},
    io::Read,
    ops::{Add, AddAssign, BitXor, BitXorAssign, Index, IndexMut},
    result::Result,
};

const BLOCK_LEN: usize = 4;
const BLOCK_LEN_INC: usize = BLOCK_LEN - 1;

// RFC 7836: id-tc26-gost-28147-param-Z (reversed)
static TABLE: [[u8; 16]; 8] = [
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1]];

#[derive(Copy, Clone, Debug, Default)]
struct Block([u8; BLOCK_LEN]);

struct BlockIntoIterator {
    block: Block,
    index: usize,
}

impl IntoIterator for Block {
    type Item = u8;
    type IntoIter = BlockIntoIterator;
    fn into_iter(self) -> Self::IntoIter {
        BlockIntoIterator {
            block: self,
            index: 0,
        }
    }
}

impl Iterator for BlockIntoIterator {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        let result: Option<u8> = match self.index {
            0..=BLOCK_LEN_INC => Some(self.block[self.index]),
            _ => None,
        };
        self.index += 1;
        result
    }
}

impl Index<usize> for Block {
    type Output = u8;
    fn index(&self, i: usize) -> &Self::Output {
        match i {
            0..=BLOCK_LEN_INC => &self.0[i],
            _ => panic!("Index {} is out of range!", i),
        }
    }
}

impl IndexMut<usize> for Block {
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        match i {
            0..=BLOCK_LEN_INC => &mut self.0[i],
            _ => panic!("Index {} is out of range!", i),
        }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[{:08b} {:08b} {:08b} {:08b}]", self[0], self[1], self[2], self[3])
    }
}

impl LowerHex for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[{:02x} {:02x} {:02x} {:02x}]", self[0], self[1], self[2], self[3])
    }
}

impl BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a ^= b)
    }
}

impl BitXor for Block {
    type Output = Self;
    fn bitxor(self, Block(rhs): Self) -> Self::Output {
        let mut block: Block = Default::default();
        block.iter_mut().zip(self.iter().zip(rhs.iter())).for_each(|(c, (a, b))| *c = a ^ b);
        block
    }
}

impl AddAssign for Block {
    fn add_assign(&mut self, rhs: Self) {
        *self = Block::from_u32(u32::wrapping_add(self.to_u32(), rhs.to_u32()))
    }
}

impl Add for Block {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Block::from_u32(u32::wrapping_add(self.to_u32(), rhs.to_u32()))
    }
}

impl Block {
    fn iter(&self) -> Iter<u8> {
        self.0.iter()
    }

    fn iter_mut(&mut self) -> IterMut<u8> {
        self.0.iter_mut()
    }

    fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    fn to_vec(&self) -> Vec<u8> {
        Vec::from(self.0)
    }

    fn from_u32(n: u32) -> Block {
        Block::from_array(n.to_be_bytes())
    }

    fn from_array(array: [u8; BLOCK_LEN]) -> Block {
        Block { 0: array }
    }

    fn from_slice(slice: &[u8]) -> Block {
        assert_eq!(BLOCK_LEN, slice.len());
        let mut result: Block = Default::default();
        result.iter_mut().zip(slice.iter()).for_each(|(a, b)| *a = *b);
        result
    }

    fn vec_to_blocks(vec: Vec<u8>) -> Vec<Block> {
        let mut result: Vec<Block> = Vec::new();
        for i in (0..vec.len()).step_by(8) {
            result.push(Block::from_slice(&vec[i..i + BLOCK_LEN]));
            result.push(Block::from_slice(&vec[i + BLOCK_LEN..i + (BLOCK_LEN << 1)]));
        }
        result
    }

    fn make_r_keys(key: &Vec<u8>) -> [Block; 32] {
        let mut r_keys: [Block; 32] = Default::default();
        for i in 0..4 {
            match i {
                0..=2 => for j in 0..8 {
                    r_keys[(i << 3) + j].0
                    .copy_from_slice(&key[j << 2..(j << 2) + 4])
                }
                3 => for j in 0..8 {
                    r_keys[(i << 3) + j].0
                    .copy_from_slice(&key[(i + 1 << 3) - (j << 2) - 4..(i + 1 << 3) - (j << 2)]);
                }
                _ => ()
            }
        }
        r_keys
    }

    fn permut(&self) -> Block {
        let mut block: Block = Default::default();
        for i in 0..BLOCK_LEN {
            block[i] = ((TABLE[i << 1][((&self[i] & 0b_11110000_u8) >> 4) as usize]) << 4) + 
                         TABLE[(i << 1) + 1][(&self[i] & 0b_00001111_u8) as usize];
        }
        block
    }

    fn enc_rounds_ecb(mut left: Block, mut right: Block, r_keys: [Block; 32]) -> (Block, Block) {
        for i in 0..31 {
            let tmp = left ^ Block::from_u32((right + r_keys[i]).permut().to_u32().rotate_left(11));
            left = right;
            right = tmp;
        }
        left = left ^ Block::from_u32((right + r_keys[31]).permut().to_u32().rotate_left(11));
        (left, right)
    }

    fn dec_rounds_ecb(mut left: Block, mut right: Block, r_keys: [Block; 32]) -> (Block, Block) {
        for i in (1..32).rev() {
            let tmp = left ^ Block::from_u32((right + r_keys[i]).permut().to_u32().rotate_left(11));
            left = right;
            right = tmp;
        }
        left = left ^ Block::from_u32((right + r_keys[0]).permut().to_u32().rotate_left(11));
        (left, right)
    }
}

fn read_file_to_vec(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut read_buffer = Vec::new();
    file.read_to_end(&mut read_buffer)?;
    Ok(read_buffer)
}

pub fn encrypt_ecb(path_in: &str, key: &Vec<u8>) {
    let mut data = read_file_to_vec(path_in).unwrap();

    // ISO/IEC 9797-1 Padding method 2
    data.push(0b_10000000_u8);
    while let 1..=15 = data.len() % 16 {
        data.push(0)
    }

    let b_data = Block::vec_to_blocks(data);
    let r_keys = Block::make_r_keys(key);
    
    let mut result: Vec<u8> = Vec::new();
    for i in (0..b_data.len()).step_by(2) {
        result.append(&mut Block::enc_rounds_ecb(b_data[i], b_data[i + 1], r_keys).0.to_vec());
        result.append(&mut Block::enc_rounds_ecb(b_data[i], b_data[i + 1], r_keys).1.to_vec());
    }

    let mut path_out = String::from(path_in);
    path_out.push_str(".enc");
    write(path_out, result).unwrap();
}

pub fn decrypt_ecb(path_in: &str, key: &Vec<u8>) {
    let data = read_file_to_vec(path_in).unwrap();
    let b_data = Block::vec_to_blocks(data);
    let r_keys = Block::make_r_keys(key);

    let mut result: Vec<u8> = Vec::new();
    for i in (0..b_data.len()).step_by(2) {
        result.append(&mut Block::dec_rounds_ecb(b_data[i], b_data[i + 1], r_keys).0.to_vec());
        result.append(&mut Block::dec_rounds_ecb(b_data[i], b_data[i + 1], r_keys).1.to_vec());
    }
    // ISO/IEC 9797-1 Padding method 2
    while let Some(i) = result.pop() {
        if i == 0b_10000000_u8 {
            break
        }
    }

    let mut path_out = String::from(path_in);
    path_out.truncate(path_out.rfind('.').unwrap());
    path_out.push_str(".dec");
    write(path_out, result).unwrap();
}
