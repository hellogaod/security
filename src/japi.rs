use crate::crypto::{aes256_cbc, base64, conver, error::ErrorKind, hex, hmac_sha512, rsa256_pksc1};
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde_json::{json, Value};

/// JSON format conversion utility
fn convert_json(feedback: Result<Value, ErrorKind>) -> String {
    let json = match feedback {
        Ok(data) => json!( {
            "success": true,
            "payload": data
        }),
        Err(e) => {
            // Provide more detailed error information in the response
            json!( {
                "success": false,
                "error": {
                    "code": e.to_string(),
                    "message": format!("Error occurred: {}", e.to_string())
                }
            })
        }
    };
    json.to_string()
}

/// -------------------------- aes256 cbc ---------------------
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_generateAesKeyAndIv(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // Generate random AES key and IV
    let (key, iv) = crate::crypto::aes256_cbc::generate_aes_key_and_iv();

    // Create a JSON response with the generated key and IV
    let json = convert_json(Ok(Value::String(
        json!( { "key": key, "iv": iv }).to_string(),
    )));

    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

// JNI function to encrypt data
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_aesEncrypt(
    env: JNIEnv,
    _class: JClass,
    data: JString,
    hex_key: JString,
    hex_iv: JString,
) -> jstring {
    let data: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();
    let hex_key: String = env
        .get_string(hex_key)
        .expect("Couldn't get Java string!")
        .into();
    let hex_iv: String = env
        .get_string(hex_iv)
        .expect("Couldn't get Java string!")
        .into();

    // Call the AES encryption function
    let result = aes256_cbc::encrypt(&data, &hex_key, &hex_iv);

    // Convert result to JSON and return as a Java string
    let json =
        convert_json(result.map(|encrypted_data| json!(encrypted_data )));

    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

// JNI function to decrypt data
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_aesDecrypt(
    env: JNIEnv,
    _class: JClass,
    encrypted_data: JString,
    hex_key: JString,
    hex_iv: JString,
) -> jstring {
    let encrypted_data: String = env
        .get_string(encrypted_data)
        .expect("Couldn't get Java string!")
        .into();
    let hex_key: String = env
        .get_string(hex_key)
        .expect("Couldn't get Java string!")
        .into();
    let hex_iv: String = env
        .get_string(hex_iv)
        .expect("Couldn't get Java string!")
        .into();

    // Call the AES decryption function
    let result = aes256_cbc::decrypt(&encrypted_data, &hex_key, &hex_iv);

    // Convert result to JSON and return as a Java string
    let json =
        convert_json(result.map(|decrypted_data| json!(decrypted_data )));

    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

/// -------------------------- hex  ---------------------
// JNI function to hex encode a string
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_hexEncode(
    env: JNIEnv,
    _class: JClass,
    data: JString,
) -> jstring {
    // Convert the JString to a Rust String
    let input: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();

    // Convert the string into a Vec<u8> (byte array)
    let input_bytes = input.as_bytes().to_vec();

    // Call the hex_encode function
    let result = hex::hex_encode(&input_bytes);

    // Convert the result to JSON and return it as a Java string
    let json = convert_json(Ok(Value::String(result)));
    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

// JNI function to hex decode a string
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_hexDecode(
    env: JNIEnv,
    _class: JClass,
    hex_str: JString,
) -> jstring {
    // Convert the Java string (hex string) to a Rust String
    let hex_str: String = env
        .get_string(hex_str)
        .expect("Couldn't get Java string!")
        .into();

    // Attempt to hex decode the string
    let result = hex::hex_decode(&hex_str);

    let decoded_str = String::from_utf8_lossy(&result).to_string();

    // Convert the result into a JSON response using convert_json
    let json = convert_json(Ok(Value::String(decoded_str)));

    // Return the JSON response as a Java string
    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

/// -------------------------- base64 ---------------------
// JNI function to base64 encode a string (JString -> base64)
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_base64Encode(
    env: JNIEnv,
    _class: JClass,
    data: JString,
) -> jstring {
    // Convert the Java string (JString) to a Rust String
    let input: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();

    // Convert the Rust String into a byte array (Vec<u8>)
    let input_bytes = input.as_bytes();

    // Call the base64 encoding function
    let result = base64::base64_encode(input_bytes);

    // Convert the result into a JSON response using convert_json
    let json = convert_json(Ok(Value::String(result)));

    // Return the JSON response as a Java string
    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

// JNI function to base64 decode a string
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_base64Decode(
    env: JNIEnv,
    _class: JClass,
    base64_str: JString,
) -> jstring {
    let base64_str: String = env
        .get_string(base64_str)
        .expect("Couldn't get Java string!")
        .into();

    // Call the base64_decode function
    let result = base64::base64_decode_to_string(&base64_str);

    // Convert the result to JSON using convert_json function
    let json = convert_json(result.map(|decoded| json!(decoded)));

    // Return the result as a Java string
    let output = env.new_string(json).expect("Couldn't create Java string!");
    output.into_raw()
}

/// -------------------------- rsa256 pksc1 ---------------------

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

/// -------------------------- hmac verify ---------------------
#[no_mangle]
pub extern "C" fn Java_com_crypto_CommonUtils_hmacVerify(
    env: JNIEnv,
    _class: JClass,
    key: JString,
    data: JString,
) -> jstring {
    let data: String = env
        .get_string(data)
        .expect("Couldn't get Java string!")
        .into();
    let key: String = env
        .get_string(key)
        .expect("Couldn't get Java string!")
        .into();

    let result = hmac_sha512::verify(&key, &data);
    let json = convert_json(result.map(|dec_data| Value::String(dec_data))); // Convert String to Value
    let output = env.new_string(json).expect("Couldn't create java string!");
    output.into_raw()
}
