# keystone-rs
Rust binding for [Keystone](http://www.keystone-engine.org/) assembler framework. Basically, it is inspired from the [original binding](https://github.com/keystone-engine/keystone/tree/master/bindings/rust) of Remco Verhoef (@remco_verhoef), but data types and constants are exported automatically using [bindgen](https://github.com/rust-lang-nursery/rust-bindgen).

It solves also a [problem](https://github.com/keystone-engine/keystone/issues/335) of the original binding in name decoration on Windows: now it can be linked with Keystone no mater what the library is static or dynamic.

## Sample
The orignal sample is used, constant names are simpler and match automatically with Keystone.

```rust
extern crate keystone;

use keystone::*;
use keystone::gen::*;

fn main() {
    let engine = Keystone::new(KS_ARCH_X86, KS_MODE_32)
        .expect("Could not initialize Keystone engine");

    engine.option(KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM)
        .expect("Could not set option to NASM syntax");

    let result = engine.asm("mov ah, 0x80", 0x0)
        .expect("Could not assemble");

    println!("ASM result: {}", result);

    if let Err(err) = engine.asm("INVALID", 0x0) {
        println!("Error: {}", err);
    }
}
```

## Acknowledgments
 - Remco Verhoef (@remco_verhoef) for the original design.
