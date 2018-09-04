pub mod gen;

use std::mem;

// re-export
pub use gen::{
    ks_arch as Arch, ks_engine as Engine, ks_err as Error, ks_mode as Mode,
    ks_opt_type as OptionType, ks_opt_value as OptionValue,
};

pub use gen::{
    ks_arch_supported, ks_asm, ks_close, ks_errno, ks_free, ks_open, ks_option, ks_strerror,
    ks_version,
};

pub use gen::{KS_API_MAJOR, KS_API_MINOR, KS_VERSION_EXTRA, KS_VERSION_MAJOR, KS_VERSION_MINOR};

macro_rules! integer_32bit_conversion {
    ($t:ty) => {
        impl From<u32> for $t {
            fn from(v: u32) -> Self {
                if mem::size_of::<$t>() != mem::size_of::<u32>() {
                    panic!("Type conversion failed")
                }
                unsafe { mem::transmute(v) }
            }
        }
        impl From<$t> for u32 {
            fn from(v: $t) -> Self {
                if mem::size_of::<$t>() != mem::size_of::<u32>() {
                    panic!("Type conversion failed")
                }
                unsafe { mem::transmute(v) }
            }
        }
        impl From<i32> for $t {
            fn from(v: i32) -> Self {
                if mem::size_of::<$t>() != mem::size_of::<i32>() {
                    panic!("Type conversion failed")
                }
                unsafe { mem::transmute(v) }
            }
        }
        impl From<$t> for i32 {
            fn from(v: $t) -> Self {
                if mem::size_of::<$t>() != mem::size_of::<i32>() {
                    panic!("Type conversion failed")
                }
                unsafe { mem::transmute(v) }
            }
        }
    };
}

integer_32bit_conversion!(Arch);
integer_32bit_conversion!(Mode);
integer_32bit_conversion!(Error);
integer_32bit_conversion!(OptionType);
integer_32bit_conversion!(OptionValue);
