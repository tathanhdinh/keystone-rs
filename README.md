# keystone-rs

Yet another Rust binding for [Keystone](http://www.keystone-engine.org/) assembler framework.

## Features
 - Hierarchical architecture: low-level binding is done by [keystone-sys](keystone-sys)
 - Fully wrapped and reexported types: no more low-level stuffs
 - Zero-copy: no additional memory allocation
 - Windows support

## Sample
```rust
use keystone::*;

fn main() {
    let engine = Keystone::from(Arch::X86, Mode::Bit32)
        .expect("Unable to initialize Keystone engine");

    engine.option(OptionType::Syntax, OptionValue::SyntaxNasm)
        .expect("Unable to set NASM syntax");

    let asm = engine.asm("mov ebp, esp", 0x4000)
        .expect("Unable to assemble");

    println!("{}", asm);
}
```

## Contributors
 - [@mteyssier](https://github.com/mteyssier)

## Acknowledgments
 - Remco Verhoef (@remco_verhoef) for the [original work](https://github.com/keystone-engine/keystone/tree/master/bindings/rust)
 - Some wrapper macros from [capstone-rs](https://github.com/capstone-rust/capstone-rs)
