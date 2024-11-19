#![feature(path_file_prefix)]

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::{env, fs};

fn cfb_mode(key: &[u8], iv: &[u8], data: &[u8], mode: Mode) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_cfb128();
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn crypt_file(
    key: &[u8],
    iv: &[u8],
    input_path: &str,
    output_path: &str,
    encry: bool,
) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let data = cfb_mode(
        key,
        iv,
        &buffer,
        if encry { Mode::Encrypt } else { Mode::Decrypt },
    )?;

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&data)?;

    Ok(())
}

fn in_dirs_f(
    dir: &str,
    key: &[u8],
    iv: &[u8],
    ext_name: &str,
    to_ext_name: &str,
    encry: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == ext_name {
                let output_path = path.with_extension(to_ext_name);
                crypt_file(
                    key,
                    iv,
                    path.to_str().unwrap(),
                    output_path.to_str().unwrap(),
                    encry,
                )?;
                println!("Encrypted: {:?}", path);
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let key = b"Im YinMo19's key";
    let iv = b"Haha...A nice iv";

    let dir = "./"; // 当前目录
    let is_decry = env::var("decry").expect("No env set yet.");

    in_dirs_f(dir, key, iv, "encry", "decry", is_decry == "true")?;

    Ok(())
}
