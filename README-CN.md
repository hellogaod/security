

# 前言

我是安卓开发，平时也喜欢搞一些其他语言，比如swift/vue/rust，菜不菜不重要，重要是喜欢，而且能达到自己想要的目标即可:**支持多平台实现rsa+aes加解密自由组合，并且还提供一些辅助功能。**

# rust项目方案

## 项目开启原因

想使用rsa+aes做一个加解密功能（http请求和响应数据加解密），base64和hex作为辅助作用。在各个平台上使用rsa+aes，发现自己的平台都调试通过了，结果发现相互之间（android和java后端）压根玩不起来，所以思索片刻，决定使用rust，这样可以打包到各个平台，解决了平台之间的兼容问题。

> 对rsa和aes算法并不是很熟悉，只是处于使用阶层。

## 利弊分析

是否需要做一个rust项目来支撑这个加解密方案，我感觉有理由说明下：

1. 有利： 各个端不需要自己去研究了，统一用rust来处理，打包成现成文件即可使用；

2. 弊端：额外增加体积，e.g.打包成so文件（arm64和v7a两个框架合计）体积在1.5M左右，不同平台大小不一样；

3. 另外：如果各端同时找一个都支持的三方加解密库来支撑是否也能满足我们的最终需求（这个问题值得讨论）。

但是我选择的方案就是rust项目。

## http加解密思路

> 这个方案的思想沿用ssl/tls加解密思想。

> 大致流程：客户端请求数据前对数据加密，服务端对接受到的数据解密，服务端处理完业务后对结果加密并且发送到客户端，客户端再对结果解密。

> aes对称加解密耗时要远远低于rsa非对称加解密耗时，这个必须了解：是我们当前项目rsa+aes的前提条件。

客户端请求服务端先生成一对密钥对：公钥`rsaPub`和私钥`rsaPrv`。`rsaPub`发送给客户端，`rsaPrv`存储在服务端。同一个设备的所有请求（或每个2小时重新生成，方案自己定）公私钥生成后保持不变，但是网络请求是一次一密，如下：

1. 客户端发送数据给服务端前加密

 - ① 客户端生成`aes`秘钥：`aesKey`、`aesIv`；
 - ② `aesKey`和`aesIv`对接口原始数据 `data` 加密，得到`dataEncrypt`;
 - ③ `rsaPub`对`aesKey`和`aesIv`加密，得到`aesKeyEncrypt`和`aesIvEncrypt`；
 - ④ 把`dataEncrypt`、`aesKeyEncrypt`和`aesIvEncrypt`传递给服务器

2. 服务端对客户端发送的加密数据解密

 - ① 先使用`rsaPrv`解密`aesKeyEncrypt`和`aesIvEncrypt`，得到`aesKey`和`aesIv`;
 - ② 使用`aesKey`和`aesIv`解密`dataEncrypt`得到`data`;
 - ③ `data`已经获取到了，这个时候服务端处理自己的业务，处理完成后得到响应数据`resData`；

3. 服务端处理完自己的业务逻辑后数据加密在发送给客户端

 - 使用`aesKey`和`aesIv`对`resData`加密得到`resDataEncrypt`,`resDataEncrypt`返回给客户端即可

4. 客户端对接收到的服务端数据解密，拿到正确的响应信息

 - 客户端接收到`resDataEncrypt`使用`aesKey`和`aesIv`解密得到响应数据`resData`。

这个是最简单的方案，实际情况还可以结合`hmac、rsaSign、rsaVerify`使用，这些方法都有，可以自行去组合使用。

# 跨平台构建

## android

### **生成so文件。**

1. 环境准备：下载NDK，官方地址为 https://developer.android.com/ndk/downloads
2. 安装编译工具：`cargo install cargo-ndk`
3. 安装编译目标：`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
4. 编译32位、64位和x86目标:

		cargo update
		cargo clean
		cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 build --release --features japi

5. 在`targget`目录下，如`aarch64-linux-android/release`的`so`文件


### 使用说明

必须在 `com.crypto`包下，名称必须是`CommonUtils`：

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


## java后端

在windows环境下：

**1.生成dll文件。**

参考android，编译本机target：`cargo update & cargo clean & cargo build --release --features japi`

2.如果是`linux`环境下，服务使用`so`文件，在响应的平台上生成`so`文件，这个暂时不在编辑范围内

## ios

**生成a文件**。必须在mac上才可以生成

1. 安装xcode sdk :参考Apple开发者网站;
2. 安装工具:`cargo install cargo-lipo`；
3. 添加 target：`rustup target add aarch64-apple-ios x86_64-apple-ios`；
4. 编译：

		cargo update
		cargo clean
		cargo lipo --release



## 微信小程序

**生成wasm 文件。**

## NodeJs原生库（我没试，可自行尝试）

**mac上生成dylib文件，windows上成dll文件。**

	<!-- macOS -->
	cargo update
	cargo clean
	cargo build --release --features napi && mv target/release/libcregis_chainlib.dylib target/release/index.node

	<!-- windows -->
	cargo update
	cargo clean
	cargo build --release --features napi && mv target/release/cregis_chainlib.dll  target/release/index.node

# 总结

目前我只做了android和windows下springboot服务的生成：

1. android生成arm64-v8a架构和armeabi-v7a架构使用的so文件；
2. windows生成dll文件；

ios和linux都是根据自己的实际操作系统和版本使用自己的操作系统生成，这里等使用到了再去补剩余代码。

详细代码大家可以咨询查阅，有问题可以找我沟通，给我指正不足。
