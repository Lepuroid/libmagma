// todo: error handling
// todo: ecb, cbc, cbf

#[cfg(test)]
mod tests {
    #[test]
    fn test_1() {
        use crate::Block;
        use crate::Cypher;

        let aa: Block = From::from(0b_01100110_10011001_00011001_01100110_u32);
        let bb: Block = From::from([
            0b_10011001_u8,
            0b_01100110_u8,
            0b_11100110_u8,
            0b_10011001_u8,
        ]);
        println!("{}\n{}", aa, bb);
        let cc: Block = Block::new_add_mod_2(aa, bb);
        let mut dd: Block = cc.clone();
        dd.add_mod_2(cc);
        println!("{}\n", dd);
    }
    #[test]
    fn test_2() {
        let mut path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv";
        let key = r#"12345678"#;
        crate::encrypt_ecb(path_in, key);
        path_in = r"C:\OneDrive\Projects\Rust\headache\log.csv.enc";
        crate::decrypt_ecb(path_in, key);
    }
}

use std::{
    fmt::{Display, Formatter, Result},
    fs::{write, OpenOptions},
    io::Read,
    ops::{Index, IndexMut},
};

const BLOCK_LEN: usize = 4;
const BLOCK_LEN_INC: usize = BLOCK_LEN - 1;

#[derive(Clone)]
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

impl From<[u8; BLOCK_LEN]> for Block {
    fn from(array: [u8; BLOCK_LEN]) -> Block {
        let block = Block { 0: array };
        block
    }
}

impl From<u32> for Block {
    fn from(n: u32) -> Block {
        let block: Block = From::from(n.to_be_bytes());
        block
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "[{:08b}, {:08b}, {:08b}, {:08b}]", self[0], self[1], self[2], self[3])
    }
}

trait Cypher {
    fn add_mod_2(&mut self, block: Block);
    fn add_mod_32(&mut self, block: Block);
    fn new_add_mod_2(a: Block, b: Block) -> Block;
    fn new_add_mod_32(a: Block, b: Block) -> Block;
}

impl Cypher for Block {
    fn add_mod_2(&mut self, block: Block) {
        self.0.iter_mut().zip(block.0.iter()).for_each(|(a, b)| *a ^= b);
    }
    fn add_mod_32(&mut self, block: Block) {
        println!("{}, {}", self, block); // Заглушка
    }
    fn new_add_mod_2(a: Block, b: Block) -> Block {
        // Спасибо Denis Lisov https://github.com/tanriol
        let mut block: Block = Default::default();
        block.0.iter_mut().zip(a.0.iter().zip(b.0.iter())).for_each(|(c, (a, b))| *c = a ^ b);
        block
    }
    fn new_add_mod_32(_a: Block, _b: Block) -> Block {
        let mut _block: Block = Default::default();
        //Сложение по модулю 32
        _block
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
