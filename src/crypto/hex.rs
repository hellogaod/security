//16进制加密
pub fn hex_encode(data: &[u8]) -> String {
    return hex::encode(data);
}

//16进制解密
pub fn hex_decode(data: &str) -> Vec<u8> {
    return hex::decode(data).unwrap();
}
