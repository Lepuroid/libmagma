// todo: error handling
// todo: ecb, cbc, cbf
// todo: utf-8/utf-16 input check
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
            0b_10011001_u8,
        ]);
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
        // Read/Write file
        let mut path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv";
        let key = r#"12345678"#;
        crate::encrypt_ecb(path_in, key);
        path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv.enc";
        crate::decrypt_ecb(path_in, key);
    }
    #[test]
    fn test_5() {
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
    fn test_6() {
        use crate::Block;

        let data: String = String::from("Hello!!!");
        let key: String = String::from("11112222333344445555666677778888");
        let r_keys: [Block; 32] = Block::make_r_keys(&key);
        Block::r2_31(data, r_keys);

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

// id-tc26-gost-28147-param-Z
static TABLE: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],   
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]];

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

    fn from_array(array: [u8; BLOCK_LEN]) -> Block {
        Block { 0: array }
    }

    fn from_u32(n: u32) -> Block {
        Block::from_array(n.to_be_bytes())
    }

    fn from_str(data: &str) -> Block {
        let mut tmp: Block = Default::default();
        let mut j = 0;
        for i in String::from(data).as_bytes().iter() {
            tmp[j] = *i;
            j += 1;
        }
        tmp
    }

    fn make_r_keys(key: &str) -> [Block; 32] {
        let mut r_keys: [Block; 32] = Default::default();
        for i in 0..4 {
            match i {
                0..=2 => for j in 0..8 {
                    r_keys[(i << 3) + j].0
                    .copy_from_slice(&key[j << 2..(j << 2) + 4].as_bytes())
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

    fn r2_31(data: String, r_keys: [Block; 32]) {
        println!("{}", data);
        let (l, r) = data.split_at(4);
        println!("{} {}", l, r);

        let mut left = Block::from_str(&l);
        let mut right = Block::from_str(&r);

        println!("{} {}", left, right);
        println!("{:x} {:x}", left, right);

        for i in 0..31 {
            let tmp = left ^ Block::from_u32((right + r_keys[i]).permut().to_u32().rotate_left(11));
            left = right;
            right = tmp;
        }
        left = left ^ Block::from_u32((right + r_keys[31]).permut().to_u32().rotate_left(11));


        for i in (1..32).rev() {
            let tmp = left ^ Block::from_u32((right + r_keys[i]).permut().to_u32().rotate_left(11));
            left = right;
            right = tmp;
        }
        left = left ^ Block::from_u32((right + r_keys[0]).permut().to_u32().rotate_left(11));

        println!("{} {}", left, right);
        println!("{:x} {:x}", left, right);
        let mut result = String::from(std::str::from_utf8(&left.0).unwrap());
        result.push_str(std::str::from_utf8(&right.0).unwrap());
        println!("{}", result)
    }
}

fn read_file(path: &str) -> Result<String, Box<dyn Error>> {
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
