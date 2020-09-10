pub(super) fn pad_1(mut vec: Vec<u8>) -> Vec<u8> {
    let add_len: usize = vec.len() % 8;
    if add_len != 0 {
        for _ in add_len..8 {
            vec.push(0);
        }
    }
    vec
}

pub(super) fn pad_2(mut vec: Vec<u8>) -> Vec<u8> {
    vec.push(0b_10000000_u8);
    pad_1(vec)
}

pub(super) fn pad_3(vec: Vec<u8>) -> Vec<u8> {
    match vec.len() % 8 {
        0 => vec,
        _ => pad_2(vec),
    }
}

pub(super) fn unpad(mut vec: Vec<u8>) -> Vec<u8> {
    while let Some(i) = vec.pop() {
        match i {
            0b_10000000_u8 => break,
            0b_00000000_u8 => (),
            _ => {
                vec.push(i);
                break;
            }
        }
    }
    vec
}
