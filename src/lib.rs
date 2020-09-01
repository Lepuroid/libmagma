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
        dd += bb + Block::from_u32(256);
        println!("cc => {}\ndd => {}\n", cc, dd);
    }
    #[test]
    fn test_3() {
        use crate::Block;
        use crate::Cypher;

        let aa: Block = Block::from_u32(0b_10100101001111000101101011000011_u32);
        println!("{}", aa);
        let _bb = aa.t_permut();
    }
    #[test]
    fn test_4() {
        let mut path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv";
        let key = r#"12345678"#;
        crate::encrypt_ecb(path_in, key);
        path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv.enc";
        crate::decrypt_ecb(path_in, key);
    }
}

use core::slice::{Iter, IterMut};
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as fmt_Result},
    fs::{write, OpenOptions},
    io::Read,
    ops::{Add, AddAssign, BitXor, BitXorAssign, Index, IndexMut},
    result::Result,
};

const BLOCK_LEN: usize = 4;
const BLOCK_LEN_INC: usize = BLOCK_LEN - 1;
static TABLE: [[u8; 16]; 8] = [[1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2],
                                [8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7],
                                [5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0],
                                [7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12],
                                [12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11],
                                [11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0],
                                [6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15],
                                [12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1]];

#[derive(Copy, Clone, Default)]
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt_Result {
        write!(f, "[{:08b} {:08b} {:08b} {:08b}]", self[0], self[1], self[2], self[3])
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

trait Cypher {
    fn iter(&self) -> Iter<u8>;
    fn iter_mut(&mut self) -> IterMut<u8>;
    fn to_u32(&self) -> u32;

    fn from_array(array: [u8; BLOCK_LEN]) -> Block {
        Block { 0: array }
    }

    fn from_u32(n: u32) -> Block {
        Block::from_array(n.to_be_bytes())
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

impl Block {
    fn t_permut(&self) -> Block {
        let mask = 0b_11110000_u8;
        let mut block: Block = Default::default();
        let mut string_1: String = String::new();
        let mut string_2: String = String::new();
        let mut string_3: String = String::new();
        for i in 0..BLOCK_LEN {
            let l4: u8 = (&self[i] & mask) >> 4;
            let r4: u8 = &self[i] & !mask;
            string_1.push_str(&format!("    {:x}{:x}   ", l4, r4));
            string_2.push_str(&format!("    ↓↓   "));
            let l4_new: u8 = TABLE[i * 2][l4 as usize];
            let r4_new: u8 = TABLE[i * 2 + 1][r4 as usize];
            string_3.push_str(&format!("    {:x}{:x}   ", l4_new, r4_new));
            block[i] = (l4_new << 4) + r4_new;
        }
        println!("{}\n{}\n{}\n{}", string_1, string_2, string_3, block);
        block
    }
}

fn read_file(path: &str) -> Result<String, Box <dyn Error>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut read_buffer = String::new();
    file.read_to_string(&mut read_buffer)?;
    Ok(read_buffer)
}

pub fn encrypt_ecb(path_in: &str, _key: &str) {
    let mut path_out = String::from(path_in);
    path_out.push_str(".enc");
    let data = read_file(path_in).unwrap();
    // Шифрование
    write(path_out, data).unwrap();
}

pub fn decrypt_ecb(path_in: &str, _key: &str) {
    let data = read_file(path_in).unwrap();
    // Дешифрование
    let mut path_out = String::from(path_in);
    path_out.truncate(path_out.rfind('.').unwrap());
    write(path_out, data).unwrap();
}
