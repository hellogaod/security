use crate::crypto::conver;
use crate::crypto::error::ErrorKind;
use base64::{decode, encode};

/// Base64 编码函数
pub fn base64_encode(data: &[u8]) -> String {
    // 使用 base64::encode 编码数据，base64::encode already returns a String
    encode(data)
}
/// Base64 解码函数，返回 Vec<u8>
pub fn base64_decode_to_vec(encoded: &str) -> Result<Vec<u8>, ErrorKind> {
    decode(encoded).map_err(|_| ErrorKind::Base64DecodeError) // Return a Vec<u8> or error
}

/// Base64 解码函数，返回 String
pub fn base64_decode_to_string(encoded: &str) -> Result<String, ErrorKind> {
    base64_decode_to_vec(encoded) // Decode the base64 string to Vec<u8>
        .and_then(|decoded| conver::u8_to_string(&decoded).map_err(|_| ErrorKind::Utf8Error)) // Convert Vec<u8> to String
}

mod test {

    use crate::crypto::base64;

    #[test]
    fn test_base64() {
        let str = "123456哈哈哈";
        let base64_encode = base64::base64_encode(str.as_bytes());
        println!("base64_encode:{}", base64_encode);
        let base64_decode = base64::base64_decode_to_string(&base64_encode).unwrap();
        println!("base64_decode:{}", base64_decode);
    }
}
