

# Preface

I am an Android developer, and I enjoy exploring other languages like Swift, Vue, and Rust. Skill level doesn’t matter; what’s important is enjoying the process and achieving my goals. My goal here is to **support cross-platform implementations of RSA+AES encryption/decryption combinations and provide auxiliary functions.**

# Rust Project Plan

## Project Motivation

I wanted to use RSA+AES for encryption and decryption (for HTTP request and response data). Base64 and Hex serve as auxiliary functionalities. While using RSA+AES across platforms, I found that each platform (Android, Java backend, etc.) worked individually, but they didn’t interoperate well. After some thought, I decided to use Rust, allowing me to compile the code for various platforms and solve compatibility issues.

> Note: I am not deeply familiar with RSA and AES algorithms; I use them primarily on an application level.

## Pros and Cons Analysis

Should we create a Rust project to support this encryption/decryption solution? Here’s my reasoning:

1. **Pros**： Each platform doesn’t need to independently develop or study encryption/decryption. Rust handles it uniformly, and the compiled binaries can be directly used.

2. **Cons**：Additional file size: For example, the compiled .so file for Android (arm64 and v7a combined) is about 1.5MB. File sizes vary by platform.

3. **Alternative**：Using a third-party library that supports all platforms might also meet our requirements (this is worth discussing).

Despite the alternative, I chose the Rust project solution.


## HTTP Encryption/Decryption Process

> This approach is inspired by SSL/TLS encryption/decryption principles.

> General workflow: The client encrypts data before sending it to the server. The server decrypts the received data, processes it, encrypts the response, and sends it back to the client. The client then decrypts the response.

>AES symmetric encryption is significantly faster than RSA asymmetric encryption. This is a key premise of our RSA+AES solution.

The client first generates a key pair on the server: a public key (`rsaPub`) and a private key (`rsaPrv`). The `rsaPub` is sent to the client, while `rsaPrv` is stored on the server. The same key pair is used for all requests from a single device (or can be regenerated every 2 hours, depending on the strategy). Each network request uses a unique key, as follows:

1. **Client-side encryption before sending data to the server:**

 - ① The client generates an AES key: `aesKey` and `aesIv`.
 - ② `aesKey` and `aesIv` encrypt the original interface data (`data`), resulting in dataEncrypt.
 - ③ `rsaPub` encrypts `aesKey` and `aesIv`, resulting in `aesKeyEncrypt` and `aesIvEncrypt`.
 - ④ `dataEncrypt`, `aesKeyEncrypt`, and `aesIvEncrypt` are sent to the server.

2. **Server-side decryption of received encrypted data:**

 - ① `rsaPrv` decrypts `aesKeyEncrypt` and `aesIvEncrypt` to obtain `aesKey` and `aesIv`.
 - ② `aesKey` and `aesIv` decrypt `dataEncrypt` to obtain `data`.
 - ③ The server processes its business logic with `data` and generates the response data (`resData`).

3. **Server-side encryption of the processed response data:**

 - `aesKey` and `aesIv` encrypt resData, resulting in resDataEncrypt. This is sent back to the client.

4. `Client-side decryption of the received server response:`

 - The client decrypts resDataEncrypt with `aesKey` and `aesIv` to obtain the response data (`resData`).

This is the simplest implementation. In practice, you can combine additional methods like `HMAC`, rsaSign, and `rsaVerify` as needed.



# Cross-Platform Builds

## android

### **Generating .so files**

1. Prepare the environment: Download the NDK from the official site:  [NDK Downloads](https://developer.android.com/ndk/downloads). 
2. Install the compilation tool：`cargo install cargo-ndk`
3. Add compilation targets：`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
4. Compile 32-bit, 64-bit, and x86 targets:

		cargo update
		cargo clean
		cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 build --release --features japi

5. The `.so` files will be located in the `target` directory, e.g., `aarch64-linux-android/release`.


### Usage Instructions

Place the files in the `com.crypto` package, and ensure the class is named `CommonUtils`:

	package com.crypto;
	
	public class CommonUtils {
	    private static CommonUtils INSTANCE;
	
	    static {
	        System.loadLibrary("common_utils");
	    }
	
	    public static CommonUtils getInstance() {
	        if (INSTANCE == null) {
	            INSTANCE = new CommonUtils();
	        }
	        return INSTANCE;
	    }
	
	    //aes生成key 和 iv
	    public native String generateAesKeyAndIv();
	
	    // aes加密
	    public native String aesEncrypt(String data, String key, String iv);
	
	    // aes解密
	    public native String aesDecrypt(String data, String key, String iv);
	
	    //hmac校验
	    public native String hmacVerify(String key, String data);
	
	    //转入16进制
	    public native String hexEncode(String data);
	
	    //转出16进制
	    public native String hexDecode(String data);
	
	    //base64加密
	    public native String base64Encode(String data);
	
	    //base64解密
	    public native String base64Decode(String data);
	
	    //生成rsa公私钥
	    public native String generateRsaKeys();
	
	    //rsa公钥加密
	    public native String rsaEncrypt(String data, String publicKey);
	
	    //rsa 私钥解密
	    public native String rsaDecrypt(String data,String privateKey);
	
	    //rsa签名
	    public native String rsaSign(String data,String privateKey);
	    //rsa验证
	    public native String rsaVerify(String data,String publickey,String sign);
	}


## Java Backend

On a Windows environment:

**1.Generate a `.dll` file: Refer to the Android steps, and compile with**

参考android，编译本机target：`cargo update & cargo clean & cargo build --release --features japi`

2.For Linux, generate `.so` files on the corresponding platform. This is outside the current scope.

## ios

Generate `.a` files. Compilation must be done on a Mac:

1. Install the Xcode SDK (refer to the Apple Developer site).
2. Install tools:`cargo install cargo-lipo`；
3. Add targets：`rustup target add aarch64-apple-ios x86_64-apple-ios`；
4. Compile：

		cargo update
		cargo clean
		cargo lipo --release



## WeChat Mini Programs

**Generate `.wasm` files.**

## Node.js Native Library (Not Tested)

**Generate `.dylib` on macOS or `.dll` on Windows:**

	<!-- macOS -->
	cargo update
	cargo clean
	cargo build --release --features napi && mv target/release/libcregis_chainlib.dylib target/release/index.node

	<!-- windows -->
	cargo update
	cargo clean
	cargo build --release --features napi && mv target/release/cregis_chainlib.dll  target/release/index.node

# Summary

Currently, I’ve completed builds for Android and Windows Spring Boot services:：

1. `.so` files for Android (arm64-v8a and armeabi-v7a architectures).
2. `.dll` files for Windows.

For iOS and Linux, builds depend on the specific operating system and version. These will be implemented as needed.

Feel free to consult the detailed code or contact me with questions or suggestions for improvement.



