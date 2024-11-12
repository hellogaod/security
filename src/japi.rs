use crate::crypto::error::ErrorKind;
use crate::crypto::rsa256_pksc1;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde_json::{json, Value};

/// JSON format conversion utility
fn convert_json(feedback: Result<Value, ErrorKind>) -> String {
    let json = match feedback {
        Ok(data) => json!({
            "success": true,
            "payload": data
        }),
        Err(e) => json!({
            "success": false,
            "payload": e.to_string()
        }),
    };
    json.to_string()
}

#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_generateRsaKeys(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = rsa256_pksc1::generate_rsa_keys()
        .map(|(public_key, private_key)| {
            json!({
                "public_key": public_key,
                "private_key": private_key.to_string()
            })
        })
        .map(|json_value| Value::Object(json_value.as_object().unwrap().clone())); // Convert to Value

    let json = convert_json(result);
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}

#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_rsaEncrypt(
    env: JNIEnv,
    _class: JClass,
    data: JString,
    public_key: JString,
) -> jstring {
    let data: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();
    let public_key: String = env
        .get_string(public_key)
        .expect("Couldn't get Java string!")
        .into();

    let result = rsa256_pksc1::encrypt_with_public_key(&public_key, &data);
    let json = convert_json(result.map(|enc_data| Value::String(enc_data))); // Convert String to Value
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}

#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_rsaDecrypt(
    env: JNIEnv,
    _class: JClass,
    encrypted_data: JString,
    private_key: JString,
) -> jstring {
    let encrypted_data: String = env
        .get_string(encrypted_data)
        .expect("Couldn't get Java string!")
        .into();
    let private_key: String = env
        .get_string(private_key)
        .expect("Couldn't get Java string!")
        .into();

    let result = rsa256_pksc1::decrypt_with_private_key(&private_key, &encrypted_data);
    let json = convert_json(result.map(|dec_data| Value::String(dec_data))); // Convert String to Value
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}

#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_rsaSign(
    env: JNIEnv,
    _class: JClass,
    data: JString,
    private_key: JString,
) -> jstring {
    let data: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();
    let private_key: String = env
        .get_string(private_key)
        .expect("Couldn't get Java string!")
        .into();

    let result = rsa256_pksc1::sign_with_private_key(&private_key, &data);
    let json = convert_json(result.map(|signature| Value::String(signature))); // Convert String to Value
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}

#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_rsaVerify(
    env: JNIEnv,
    _class: JClass,
    data: JString,
    public_key: JString,
    signature: JString,
) -> jstring {
    let data: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();
    let public_key: String = env
        .get_string(public_key)
        .expect("Couldn't get Java string!")
        .into();
    let signature: String = env
        .get_string(signature)
        .expect("Couldn't get Java string!")
        .into();

    let result = rsa256_pksc1::verify_with_public_key(&public_key, &data, &signature);
    let json = convert_json(result.map(|is_valid| Value::Bool(is_valid))); // Convert bool to Value
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}
