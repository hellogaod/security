use crate::crypto::error::ErrorKind;
use base64::{decode, encode};

/// Base64 编码函数
pub fn base64_encode(data: &[u8]) -> String {
    // 使用 base64::encode 编码数据
    let encode_data = encode(data);
    return encode_data;
}

/// Base64 解码函数
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, ErrorKind> {
    // 使用 base64::decode 解码字符串
    return match decode(encoded) {
        Ok(decoded) => {
            // 尝试将字节数据转换为 UTF-8 字符串
            Ok(decoded)
        }
        Err(_) => Err(ErrorKind::Base64DecodeError), // 如果解码失败，返回自定义错误
    };
}

mod test {
    
    use crate::crypto::base64;
    use crate::crypto::conver;
    #[test]
    fn test_base64() {
        let str = "123456";
        let base64_encode = base64::base64_encode(str.as_bytes());
        println!("base64_encode:{}", base64_encode);
        let base64_decode = base64::base64_decode(&base64_encode).unwrap();
        println!(
            "base64_decode:{}",
            conver::u8_to_string(&base64_decode).unwrap()
        );
    }
}
