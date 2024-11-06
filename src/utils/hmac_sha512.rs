use hmac::{Hmac, Mac};
use sha2::Sha512;
type HmacSha512 = Hmac<Sha512>;
use crate::utils::hex;
use crate::utils::error::ErrorKind;


/// 使用 HMAC-SHA512 进行加密
pub fn hmac_sha512(key: &str, data: &str) -> Result<String,ErrorKind> {
    let mut mac = HmacSha512::new_from_slice(key.as_bytes()).map_err(|_| ErrorKind::HmacError)?;
    mac.update(data.as_bytes());

    // 获取 HMAC 的结果
    let result = mac.finalize().into_bytes();

    Ok(hex::hex_encode(&result)) // 返回 HMAC 结果
}

mod test {
    use crate::utils::conver;
    use crate::utils::hmac_sha512::hmac_sha512;
    #[test]
    fn test_hmac_sha512() {
        let key = "secret_key";
        let data = "data_to_hash";

        let result = hmac_sha512(key, data).unwrap();

        println!("结果： {}", result);
    }
}
