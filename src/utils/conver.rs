
use crate::utils::error::ErrorKind;

//[u8]转换成utf8编码字符串
pub fn u8_to_string(bytes: &[u8]) -> Result<String, ErrorKind> {
    return match String::from_utf8(bytes.to_vec()){
        Ok(utf8_str) => {
            // 尝试将字节数据转换为 UTF-8 字符串
            Ok(utf8_str)
        }
        Err(_) => Err(ErrorKind::Utf8Error), // 如果解码失败，返回自定义错误
    }
}
