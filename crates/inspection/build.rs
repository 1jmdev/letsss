use std::{
    env, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const SOURCES: [&str; 4] = ["clients", "modules", "rules", "environment"];

fn main() {
    let mut merged = toml::Table::new();
    for source in SOURCES {
        let path = format!("signatures/{source}.toml");
        println!("cargo:rerun-if-changed={path}");
        let text = fs::read_to_string(&path).expect("signature source is readable");
        let table: toml::Table = toml::from_str(&text).expect("signature source is valid TOML");
        merged.extend(table);
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_nanos();
    let key = (nanos as u64 ^ (nanos >> 64) as u64 | 1).to_le_bytes();
    let mut encoded = serde_json::to_vec(&merged).expect("signature table serializes");
    encoded
        .iter_mut()
        .enumerate()
        .for_each(|(index, byte)| *byte ^= key[index % key.len()].wrapping_add(index as u8));

    let output = env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let output = Path::new(&output);
    fs::write(output.join("signatures.bin"), encoded).expect("signature blob is writable");
    fs::write(
        output.join("signature_key.rs"),
        format!("const SIGNATURE_KEY: [u8; 8] = {key:?};\n"),
    )
    .expect("signature key is writable");
}
