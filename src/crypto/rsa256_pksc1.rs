use crate::crypto::base64;
use crate::crypto::error::ErrorKind;
use rand::rngs::OsRng;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::PublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing; // 引入 zeroize

/// 生成 RSA 公私钥对，返回 PEM 格式的公钥和私钥字符串
pub fn generate_rsa_keys() -> Result<(String, Zeroizing<String>), ErrorKind> {
    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|_| ErrorKind::RsaGenerateKeyError)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| ErrorKind::RsaGenerateKeyError)?;

    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| ErrorKind::RsaGenerateKeyError)?;

    return Ok((public_key_pem, private_key_pem));
}

/// 使用公钥加密数据，并返回 Base64 编码的加密数据
pub fn encrypt_with_public_key(public_key_pem: &str, data: &str) -> Result<String, ErrorKind> {
    // 将 PEM 格式的公钥转换为 RsaPublicKey
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ErrorKind::RsaEncryptionError)?;

    // 使用 PKCS1v15 填充模式
    let padding = PaddingScheme::PKCS1v15Encrypt;
    let encrypted_data = public_key
        .encrypt(&mut OsRng, padding, data.as_bytes())
        .map_err(|_| ErrorKind::RsaEncryptionError)?;

    Ok(base64::base64_encode(&encrypted_data)) // Base64 编码返回
}

/// 使用私钥解密 Base64 编码的加密数据
pub fn decrypt_with_private_key(
    private_key_pem: &str,
    encrypted_data: &str,
) -> Result<String, ErrorKind> {
    // 将 PEM 格式的私钥转换为 RsaPrivateKey
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| ErrorKind::RsaDecryptionError)?;

    // 解码 Base64 加密数据
    let encrypted_data = base64::base64_decode(encrypted_data)?;

    // 使用 PKCS1v15 填充模式
    let padding = PaddingScheme::PKCS1v15Encrypt;
    let decrypted_data = private_key
        .decrypt(padding, &encrypted_data)
        .map_err(|_| ErrorKind::RsaDecryptionError)?;

    Ok(String::from_utf8(decrypted_data).map_err(|_| ErrorKind::Utf8Error)?) // 将解密的字节转换为字符串
}

/// 使用私钥对数据进行签名
pub fn sign_with_private_key(private_key_pem: &str, data: &str) -> Result<String, ErrorKind> {
    // 将 PEM 格式的私钥转换为 RsaPrivateKey
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|_| ErrorKind::RsaSignError)?;

    // 对数据进行 SHA256 哈希
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hashed = hasher.finalize();

    // 使用 PKCS1v15 填充模式进行签名
    let padding = PaddingScheme::PKCS1v15Sign {
        hash_len: Some(32),   // SHA256 哈希长度
        prefix: Box::new([]), // 前缀字节，通常为空
    };

    // 使用私钥对哈希进行签名
    let signature = private_key
        .sign(padding, &hashed)
        .map_err(|_| ErrorKind::RsaSignError)?;

    // 将签名转换为 Base64 编码返回
    Ok(base64::base64_encode(&signature))
}

/// 使用公钥验证签名
pub fn verify_with_public_key(
    public_key_pem: &str,
    data: &str,
    signature_base64: &str,
) -> Result<bool, ErrorKind> {
    // 将 PEM 格式的公钥转换为 RsaPublicKey
    let public_key =
        RsaPublicKey::from_public_key_pem(public_key_pem).map_err(|_| ErrorKind::RsaVerifyError)?;

    // 对数据进行 SHA256 哈希
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hashed = hasher.finalize();

    // 解码 Base64 编码的签名
    let signature = base64::base64_decode(signature_base64)?;

    // 使用 PKCS1v15 填充模式进行签名
    let padding = PaddingScheme::PKCS1v15Sign {
        hash_len: Some(32),   // SHA256 哈希长度
        prefix: Box::new([]), // 前缀字节，通常为空
    };

    // 使用公钥验证签名，返回 Result<()>
    match public_key.verify(padding, &hashed, &signature) {
        Ok(()) => Ok(true),  // 如果验证通过，返回 true
        Err(_) => Ok(false), // 如果验证失败，返回 false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time;

    #[test]
    fn test_rsa_encryption_decryption() {
       
        // 生成公私钥对
        let (public_key, private_key) = generate_rsa_keys().unwrap();

        // 要加密的消息
        let message = "Hello, RSA PKCS1v15!";

        // 使用公钥加密
        let encrypted_message =
            encrypt_with_public_key(&public_key, message).expect("Encryption failed");
        println!("Encrypted message: {}", encrypted_message);

        // 使用私钥解密
        let decrypted_message =
            decrypt_with_private_key(&private_key, &encrypted_message).expect("Decryption failed");
        println!("Decrypted message: {}", decrypted_message);

        // 检查解密后的消息是否与原始消息相同
        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn test_rsa_sign_verify() {
        // 生成公私钥对
        let (public_key, private_key) = generate_rsa_keys().unwrap();

        // 要签名的消息
        let message = "Hello, RSA PKCS1v15 Sign and Verify!";

        // 使用私钥对消息进行签名
        let signature = sign_with_private_key(&private_key, message).expect("Signing failed");

        println!("Signature: {}", signature);

        // 使用公钥校验签名
        let is_valid = verify_with_public_key(&public_key, message, &signature)
            .expect("Signature verification failed");

        // 校验签名是否有效
        assert!(is_valid);
    }
}
