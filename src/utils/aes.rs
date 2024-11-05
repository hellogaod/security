use crypto::aes;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;
use rand::Rng;

/// ------------------------------------------- AES-256-CBC 模式加密、解密、生成32位aeskey和16位iv start -----------------------------------------------------
/// Encrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
pub fn aes256_cbc_encrypt(
    data: &[u8],
    key: &[u8; 32], // 修改为字节数组
    iv: &[u8; 16],  // 修改为字节数组
) -> Result<Vec<u8>, SymmetricCipherError> {
    // Validate key and IV lengths
    validate_key_and_iv(key, iv);

    let mut encryptor = aes::cbc_encryptor(KeySize256, key, iv, PkcsPadding);

    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut final_result = Vec::new();

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => break,
            _ => continue,
        }
    }

    Ok(final_result)
}

/// Decrypt a buffer with the given key and iv using AES256/CBC/Pkcs encryption.
pub fn aes256_cbc_decrypt(
    data: &[u8],
    key: &[u8; 32], // 修改为字节数组
    iv: &[u8; 16],  // 修改为字节数组
) -> Result<Vec<u8>, SymmetricCipherError> {
    // Validate key and IV lengths
    validate_key_and_iv(key, iv);

    let mut decryptor = aes::cbc_decryptor(KeySize256, key, iv, PkcsPadding);

    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut final_result = Vec::new();

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => break,
            _ => continue,
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

/// ------------------------------------------- AES-256-CBC 模式加密、解密、生成32位aeskey和16位iv end -----------------------------------------------------



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
