// todo: key input
// todo: data slicing into 64-bit blocks
// todo: length control
// todo: interactive mode (CLI)
// todo: error handling
// todo: ecb, cbc, cbf
// todo: implement u256?..

#[cfg(test)]
mod tests {
    #[test]
    fn test_1() {
        // ^ and ^= overload
        use crate::Block;

        let aa: Block = Block::from_u32(0b_01100110_10011001_00011001_01100110_u32);
        let bb: Block = Block::from_array([
            0b_10011001_u8,
            0b_01100110_u8,
            0b_11100110_u8,
            0b_10011001_u8]);
        println!("aa => {}\nbb => {}", aa, bb);
        let cc: Block = aa ^ bb;
        let mut dd: Block = cc;
        dd ^= cc;
        println!("cc => {}\ndd => {}\n", cc, dd);
    }
    #[test]
    fn test_2() {
        // + and += overload
        use crate::Block;

        let aa: Block = Block::from_u32(0b_10000000_00000000_00000000_00000000_u32);
        let bb: Block = Block::from_array([
            0b_01000000_u8,
            0b_00000000_u8,
            0b_00000000_u8,
            0b_00000000_u8,
        ]);
        println!("aa => {}\nbb => {}", aa, bb);
        let cc: Block = aa + bb;
        let mut dd: Block = cc;
        dd += bb + Block::from_u32(257);
        println!("cc => {}\ndd => {}\n", cc, dd);
    }
    #[test]
    fn test_3() {
        // T Permutation
        use crate::Block;

        let aa: Block = Block::from_u32(0b_10100101001111000101101011000011_u32);
        let bb = aa.permut();
        println!("{:x}\n ↓↓ ↓↓ ↓↓ ↓↓\n{:x}", aa, bb);
    }
    #[test]
    fn test_4() {
        // Round keys from 256-bit key
        use crate::Block;

        let key: &str = "11112222333344445555666677778888";
        let r_keys: [Block; 32] = Block::make_r_keys(&key);
        let mut i: u8 = 0;
        for x in r_keys.iter() {
            i += 1;
            println!("{}{}{}{} => {:x} => {}", x[0] as char, x[1] as char,
                                               x[2] as char, x[3] as char, x, x);
            match i {
                8 => {i = 0; println!()},
                _ => (),
            }
        }
    }
    #[test]
    fn test_5() {
        // Encrypt-Decrypt
        use crate::*;
        let mut path_in: String = String::from(r"C:\OneDrive\Projects\Rust\libmagma\hello.txt");
        let key = "11112222333344445555666677778888";

        let mut data = read_file(&path_in).unwrap();
        println!("{}", String::from_utf8_lossy(&data));
        
        encrypt_ecb(&path_in, key);
        path_in.push_str(".enc");
        data = read_file(&path_in).unwrap();
        println!("{}", String::from_utf8_lossy(&data));

        decrypt_ecb(&path_in, key);
        path_in = path_in.replace(".enc", ".dec");
        data = read_file(&path_in).unwrap();
        println!("{}", String::from_utf8_lossy(&data));
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

// RFC 7836: id-tc26-gost-28147-param-Z
static TABLE: [[u8; 16]; 8] = [
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2]];

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

    fn from_array(array: [u8; BLOCK_LEN]) -> Block {
        Block { 0: array }
    }

    fn from_u32(n: u32) -> Block {
        Block::from_array(n.to_be_bytes())
    }

    fn from_slice(slice: &[u8]) -> Block {
        assert_eq!(BLOCK_LEN, slice.len());
        let mut result: Block = Default::default();
        result.iter_mut().zip(slice.iter()).for_each(|(a, b)| *a = *b);
        result
    }

    fn make_r_keys(key: &str) -> [Block; 32] {
        let mut r_keys: [Block; 32] = Default::default();
        for i in 0..4 {
            match i {
                0..=2 => for j in 0..8 {
                    r_keys[(i << 3) + j].0
                    .copy_from_slice(&key[j << 2..(j << 2) + 4]
                    .as_bytes())
                }
                3 => for j in 0..8 {
                    r_keys[(i << 3) + j].0
                    .copy_from_slice(&key[(i + 1 << 3) - (j << 2) - 4..(i + 1 << 3) - (j << 2)]
                    .as_bytes());
                }
                _ => ()
            }
        }
        r_keys
    }

    fn permut(&self) -> Block {
        let mask = 0b_11110000_u8;
        let mut block: Block = Default::default();
        for i in 0..BLOCK_LEN {
            let l4: u8 = (&self[i] & mask) >> 4;
            let r4: u8 = &self[i] & !mask;
            let l4_new: u8 = TABLE[i << 1][l4 as usize];
            let r4_new: u8 = TABLE[(i << 1) + 1][r4 as usize];
            block[i] = (l4_new << 4) + r4_new;
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

fn read_file(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut read_buffer = Vec::new();
    file.read_to_end(&mut read_buffer)?;
    Ok(read_buffer)
}

pub fn encrypt_ecb(path_in: &str, key: &str) {
    // Вхлоп
    let mut path_out = String::from(path_in);
    path_out.push_str(".enc");
    let data = read_file(path_in).unwrap();
    // Шифрование
    let (l, r) = data.split_at(BLOCK_LEN);
    let r_keys = Block::make_r_keys(&key);
    let (left, right) = Block::enc_rounds_ecb(Block::from_slice(l), Block::from_slice(r), r_keys);
    // Выхлоп
    let mut result = left.to_vec();
    result.extend(right.iter());
    write(path_out, result).unwrap();
}

pub fn decrypt_ecb(path_in: &str, key: &str) {
    // Вхлоп
    let data = read_file(path_in).unwrap();
    // Дешифрование
    let (l, r) = data.split_at(BLOCK_LEN);
    let r_keys = Block::make_r_keys(&key);
    let (left, right) = Block::dec_rounds_ecb(Block::from_slice(l), Block::from_slice(r), r_keys);
    // Выхлоп
    let mut result = left.to_vec();
    result.extend(right.iter());
    let mut path_out = String::from(path_in);
    path_out.truncate(path_out.rfind('.').unwrap());
    path_out.push_str(".dec");
    write(path_out, result).unwrap();
}
