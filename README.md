# keystone-rs

Yet another Rust binding for [Keystone](http://www.keystone-engine.org/) assembler framework.

## Features
 - Hierarchical architecture: low-level binding is done by [keystone-sys](keystone-sys)
 - Fully wrapped and reexported types: no more low-level stuffs :)
 - Windows support, yeah!!!

## Sample
```rust
extern crate keystone;

use keystone::*;

fn main() {
    let engine = Keystone::new(Arch::X86, Mode::Bit32)
        .expect("Unable to initialize Keystone engine");

    engine.option(OptionType::Syntax, OptionValue::SyntaxNasm)
        .expect("Unable to set NASM syntax");

    let asm = engine.asm("mov ebp, esp", 0x4000)
        .expect("Unable to assemble");

    println!("{}", asm);
}
```

## Acknowledgments
 - Remco Verhoef (@remco_verhoef) for the [original work](https://github.com/keystone-engine/keystone/tree/master/bindings/rust)
 - Some wrapper macros from [capstone-rs](https://github.com/capstone-rust/capstone-rs)
