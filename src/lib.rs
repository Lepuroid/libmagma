// todo: error handling
// todo: ecb, cbc, cbf

#[cfg(test)]
mod tests {
    #[test]
    fn test_1() {
        use crate::Block;
        use crate::Cypher;

        let aa: Block = Block::from_u32(0b_01100110_10011001_00011001_01100110_u32);
        let bb: Block = Block::from_array([0b_10011001_u8, 0b_01100110_u8,
                                           0b_11100110_u8, 0b_10011001_u8]);
        println!("aa => {}\nbb => {}", aa, bb);
        let cc: Block = aa ^ bb;
        let mut dd: Block = cc;
        dd ^= cc;
        println!("cc => {}\ndd => {}\n", cc, dd);
    }
    #[test]
    fn test_2() {
        use crate::Block;
        use crate::Cypher;

        let aa: Block = Block::from_u32(0b_10000000_00000000_00000000_00000000_u32);
        let bb: Block = Block::from_array([0b_01000000_u8, 0b_00000000_u8,
                                           0b_00000000_u8, 0b_00000000_u8]);
        println!("aa => {}\nbb => {}", aa, bb);
        let cc: Block = aa + bb;
        let mut dd: Block = cc;
        dd += bb ;
        println!("cc => {}\ndd => {}\n", cc, dd);
    }
    #[test]
    fn test_3() {
        let mut path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv";
        let key = r#"12345678"#;
        crate::encrypt_ecb(path_in, key);
        path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv.enc";
        crate::decrypt_ecb(path_in, key);
    }
}

use core::slice::{Iter, IterMut};
use std::{
    fmt::{Display, Formatter, Result},
    fs::{write, OpenOptions},
    io::Read,
    ops::{Add, AddAssign, BitXor, BitXorAssign, Index, IndexMut},
};

const BLOCK_LEN: usize = 4;
const BLOCK_LEN_INC: usize = BLOCK_LEN - 1;

#[derive(Copy, Clone)]
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
        let result = match self.index {
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

impl Default for Block {
    fn default() -> Block {
        Block { 0: [0; BLOCK_LEN] }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "[{:08b}, {:08b}, {:08b}, {:08b}]", self[0], self[1], self[2], self[3])
    }
}

impl BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a ^= b)
    }
}

impl BitXor for Block {
    type Output = Self;
    fn bitxor(self, Block(rhs): Self) -> Self {
        let mut block: Block = Default::default();
        block.iter_mut().zip(self.iter().zip(rhs.iter())).for_each(|(c, (a, b))| *c = a ^ b);
        block
    }
}

impl AddAssign for Block {
    fn add_assign(&mut self, rhs: Self) {
        *self = Block::from_u32(u32::saturating_add(self.to_u32(), rhs.to_u32()))
    }
}

impl Add for Block {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Block::from_u32(u32::saturating_add(self.to_u32(), rhs.to_u32()))
    }

}

trait Cypher {
    fn iter(&self) -> Iter<u8>;
    fn iter_mut(&mut self) -> IterMut<u8>;
    fn to_u32(&self) -> u32;

    fn from_array(array: [u8; BLOCK_LEN]) -> Block {
        let block = Block { 0: array };
        block
    }

    fn from_u32(n: u32) -> Block {
        let block: Block = Block::from_array(n.to_be_bytes());
        block
    }
}

impl Cypher for Block {
    fn iter(&self) -> Iter<u8> {
        self.0.iter()
    }

    fn iter_mut(&mut self) -> IterMut<u8> {
        self.0.iter_mut()
    }

    fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

fn read_file(path: &str) -> String {
    let mut file = OpenOptions::new().read(true).open(path).unwrap();
    let mut read_buffer = String::new();
    file.read_to_string(&mut read_buffer).unwrap();
    read_buffer
}

pub fn encrypt_ecb(path_in: &str, _key: &str) {
    let mut path_out = String::from(path_in);
    path_out.push_str(".enc");
    let data = read_file(path_in);
    // Шифрование
    write(path_out, data).unwrap();
}

pub fn decrypt_ecb(path_in: &str, _key: &str) {
    let data = read_file(path_in);
    // Дешифрование
    let mut path_out = String::from(path_in);
    path_out.truncate(path_out.rfind('.').unwrap());
    write(path_out, data).unwrap();
}
