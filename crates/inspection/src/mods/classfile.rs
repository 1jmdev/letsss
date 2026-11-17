//! Minimal Java class file reader exposing constant pool UTF-8 entries.

const MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
const POOL_COUNT_OFFSET: usize = 8;
const POOL_START: usize = 10;

/// Visits every `CONSTANT_Utf8` entry; returns `false` when the class file is malformed.
pub fn constants(class: &[u8], mut visit: impl FnMut(&[u8])) -> bool {
    if class.get(..4) != Some(&MAGIC) {
        return false;
    }
    let Some(count) = read_u16(class, POOL_COUNT_OFFSET) else {
        return false;
    };
    let mut position = POOL_START;
    let mut index = 1;
    while index < count {
        let Some(tag) = class.get(position) else {
            return false;
        };
        position += match tag {
            1 => {
                let Some(length) = read_u16(class, position + 1) else {
                    return false;
                };
                let Some(text) = class.get(position + 3..position + 3 + length as usize) else {
                    return false;
                };
                visit(text);
                3 + length as usize
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => 5,
            5 | 6 => {
                index += 1;
                9
            }
            7 | 8 | 16 | 19 | 20 => 3,
            15 => 4,
            _ => return false,
        };
        index += 1;
    }
    true
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
}
