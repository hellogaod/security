//extern crate cbindgen; 用于在 build.rs 中导入 cbindgen 依赖库。cbindgen 是一个工具，用于根据 Rust 源代码生成与 C 语言兼容的头文件（.h 文件），方便其他语言调用 Rust 库。
extern crate cbindgen;

fn main() {
    //这段代码的作用是在构建 Rust 项目时，自动生成一个名为 chainlib.h 的 C 头文件，
    //方便其他使用 C 或兼容 C 的语言（如 C++、Python 通过 C API 等）调用 Rust 库的功能。这是为跨语言集成和库开发时常见的做法。
    cbindgen::Builder::new()//创建一个新的 cbindgen 构建器实例，用于配置如何生成头文件
        .with_src("./src/cbinding.rs")//设置 cbindgen 使用位于 ./src/cbinding.rs 的 Rust 文件作为生成 C 绑定的源代码文件。
        .with_language(cbindgen::Language::C)//表示生成的头文件将是 C 语言的绑定。
        .generate()//生成绑定。如果生成失败，将抛出一个错误。
        .expect("Unable to generate bindings")
        .write_to_file("chainlib.h");//将生成的 C 头文件输出到 chainlib.h 文件中:内容是通过 cbindgen 从 Rust 源代码中提取并生成的

}
