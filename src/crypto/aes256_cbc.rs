use crate::crypto::base64;
use crate::crypto::error::ErrorKind;
use crate::crypto::hex;

use crypto::aes;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rand::Rng; // 引用 error.rs 中的 AesError

/// Encrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
/// 返回加密后的结果（字节数组），可能返回错误
pub fn encrypt(
    data: &str,
    hex_key: &str, // AES 密钥，32 字节
    hex_iv: &str,  // 初始化向量（IV），16 字节
) -> Result<String, ErrorKind> {
    // Validate key and IV lengths
    let _ = validate_key_and_iv(hex_key, hex_iv);

    let key = hex::hex_decode(hex_key);
    let iv = hex::hex_decode(hex_iv);

    let mut encryptor = aes::cbc_encryptor(KeySize256, &key, &iv, PkcsPadding);

    let mut buffer = vec![0; data.len() + 16]; // 加上 padding 空间
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(data.as_bytes());
    let mut final_result = Vec::new();

    loop {
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                final_result.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .copied(),
                );
                if let crypto::buffer::BufferResult::BufferUnderflow = result {
                    break;
                }
            }
            Err(_) => return Err(ErrorKind::AesDecryptError),
        }
    }

    Ok(base64::base64_encode(&final_result))
}

/// Decrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
/// 解密数据，返回解密后的utf8字符串
pub fn decrypt(data: &str, hex_key: &str, hex_iv: &str) -> Result<String, ErrorKind> {
    // Validate key and IV lengths
    let _ = validate_key_and_iv(hex_key, hex_iv);

    let key = hex::hex_decode(hex_key);
    let iv = hex::hex_decode(hex_iv);

    let mut decryptor = aes::cbc_decryptor(KeySize256, &key, &iv, PkcsPadding);
    let decoded_data = base64::base64_decode(data).unwrap();

    let mut buffer = vec![0; data.len()]; // 创建足够大的缓冲区
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(&decoded_data);
    let mut final_result = Vec::new();

    loop {
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                final_result.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .copied(),
                );
                if let crypto::buffer::BufferResult::BufferUnderflow = result {
                    break;
                }
            }
            Err(_) => return Err(ErrorKind::AesDecryptError),
        }
    }

    // 尝试将解密结果转换为 UTF-8 字符串
    return std::str::from_utf8(&final_result)
        .map_err(|_| ErrorKind::Utf8Error)
        .map(|s| s.to_string()); // 如果解密结果不是有效的 UTF-8 字符串，返回错误
}

/// Validate the key and IV lengths
pub fn validate_key_and_iv(key: &str, iv: &str) -> Result<(), ErrorKind> {
    if key.is_empty() || iv.is_empty() {
        return Err(ErrorKind::InvalidData);
    }

    let keylen = hex::hex_decode(key).len();

    if keylen != 32 {
        return Err(ErrorKind::InvalidKeyLength(keylen));
    }

    let ivlen = hex::hex_decode(iv).len();
    if ivlen != 16 {
        return Err(ErrorKind::InvalidIvLength(ivlen));
    }
    Ok(())
}

/// Generate a random AES key (32 bytes) and IV (16 bytes)
pub fn generate_aes_key_and_iv() -> (String, String) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let iv: [u8; 16] = rng.gen();
    (hex::hex_encode(&key), hex::hex_encode(&iv))
}

///AES-256-CBC 模式加密、解密、生成32位aeskey和16位iv
/// 1. 采用256为cbc模式加解密
/// 2. aeskey是32为，iv是16为；
/// 3.aes加密后又使用了base64加密，aes解密数据前又实用了base64解密
/// 4. aeskey和iv生成的时候都转换成16进制加密，所以使用时需要进行16进制解密
/// 5. aes加密后的数据转换成utf-8类型字符串
/// #[test] aes生成aeskey和iv后完成加解密测试
#[test]
fn test_aes256_cbc() {
    // 生成 AES 密钥和 IV
    let (hex_key, hex_iv) = generate_aes_key_and_iv();

    // 验证密钥和 IV 的长度
    let _ = validate_key_and_iv(&hex_key, &hex_iv).unwrap(); // 确保没有错误

    println!("hex_aeskey: {} ,hex_iv: {}", hex_key, hex_iv);

    // 设置需要加密的字符串
    let data = "Hello, world!";

    // 加密操作
    let encrypted_data = encrypt(data, &hex_key, &hex_iv).unwrap();

    println!("加密后的数据：{}", encrypted_data);

    // 解密操作
    let decrypted_data = decrypt(&encrypted_data, &hex_key, &hex_iv).unwrap();

    assert_eq!(data, decrypted_data);
    println!("解密后的数据: {}", decrypted_data);
}
