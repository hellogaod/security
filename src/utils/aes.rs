///AES-256-CBC 模式加密、解密、生成32位aeskey和16位iv
/// 1. 采用256为cbc模式加解密
/// 2. aeskey是32为，iv是16为；
/// 3.aes加密后又使用了base64加密，aes解密数据前又实用了base64解密
/// 4. aeskey和iv生成的时候都转换成16进制

use crypto::aes;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;
use rand::Rng;
use base64::{encode, decode};

/// Encrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
/// 返回加密后的结果（字节数组），可能返回错误
pub fn aes256_cbc_encrypt(
    data: &[u8],
    key: &[u8; 32], // AES 密钥，32 字节
    iv: &[u8; 16],  // 初始化向量（IV），16 字节
) -> Result<String, SymmetricCipherError> {
    // Validate key and IV lengths
    validate_key_and_iv(key, iv);

    let mut encryptor = aes::cbc_encryptor(KeySize256, key, iv, PkcsPadding);

    let mut buffer = vec![0; data.len() + 16]; // 加上 padding 空间
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut final_result = Vec::new();

    loop {
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());
                if let crypto::buffer::BufferResult::BufferUnderflow = result {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(encode(final_result))

}

/// Decrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
/// 解密数据，返回解密后的字节数据
pub fn aes256_cbc_decrypt(
    data: &str,
    key: &[u8; 32], 
    iv: &[u8; 16],  
) -> Result<Vec<u8>, SymmetricCipherError> {
    // Validate key and IV lengths
    validate_key_and_iv(key, iv);

    let mut decryptor = aes::cbc_decryptor(KeySize256, key, iv, PkcsPadding);
    let decoded_data = decode(data).map_err(|_| "base64 decode is error").unwrap();

    let mut buffer = vec![0; data.len()]; // 创建足够大的缓冲区
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(&decoded_data);
    let mut final_result = Vec::new();

    loop {
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());
                if let crypto::buffer::BufferResult::BufferUnderflow = result {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(final_result)
}

/// Validate the key and IV lengths
pub fn validate_key_and_iv(key: &[u8], iv: &[u8]) -> Result<(), &'static str> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes long.");
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes long.");
    }
    Ok(())
}

/// Generate a random AES key (32 bytes) and IV (16 bytes)
pub fn generate_aes_key_and_iv() -> ([u8; 32], [u8; 16]) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let iv: [u8; 16] = rng.gen();
    (key, iv)
}



/// #[test] aes生成aeskey和iv后完成加解密测试
#[test]
fn test_aes256_cbc() {
    // 生成 AES 密钥和 IV
    let (key, iv) = generate_aes_key_and_iv();

    // 验证密钥和 IV 的长度
    validate_key_and_iv(&key, &iv).unwrap(); // 确保没有错误

    let key_hex = hex::encode(&key);
    let iv_hex = hex::encode(&iv);

    println!("aeskey: {}, iv: {}", key_hex, iv_hex);

    // 设置需要加密的字符串
    let data = "Hello, world!";

    // 加密操作
    let encrypted_data = aes256_cbc_encrypt(data.as_bytes(), &key, &iv).unwrap();

    // 解密操作
    let decrypted_data = aes256_cbc_decrypt(&encrypted_data, &key, &iv).unwrap();

    // 转为原始字符串信息
    let result = std::str::from_utf8(&decrypted_data).unwrap();

    assert_eq!(data, result);
    println!("Decrypted: {}", result);
}
