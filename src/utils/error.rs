// error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorKind {

    #[error("invalid number of key length: {0}")]
    InvalidKeyLength(usize),
    #[error("invalid number of iv length: {0}")]
    InvalidIvLength(usize),
    #[error("invalid data")]
    InvalidData,
    #[error("aes decrypt error")]
    AesDecryptError,
    #[error("utf8 error")]
    Utf8Error,
    #[error("base64 decode error")]
    Base64DecodeError,
    #[error("hmac error")]
    HmacError,
    #[error("rsa decode error")]
    RsaDecodeError,
}
