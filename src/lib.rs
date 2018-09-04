extern crate keystone_sys as kss;

mod reexport;

pub use reexport::*;
use std::{convert::From, error, ffi::CStr, fmt};


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use error::Error;
        write!(f, "{}", self.description())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        unsafe {
            CStr::from_ptr(kss::ks_strerror(From::from(*self)))
                .to_str()
                .unwrap()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub struct Assembly {
    pub statement_count: usize,
    pub encoding: Vec<u8>,
}

impl std::fmt::Display for Assembly {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let encoding_strs = self
            .encoding
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "{}", encoding_strs)
    }
}

pub struct Keystone {
    engine: *mut kss::Engine,
}

impl Keystone {
    /// Create new instance of Keystone engine.
    pub fn new(arch: Arch, mode: Mode) -> Result<Self, Error> {
        let (major, minor, _) = self::version();
        if (major, minor) != Keystone::binding_version() {
            Err(Error::Version)
        } else {
            let mut engine: *mut kss::Engine = std::ptr::null_mut();
            let err = unsafe {
                kss::ks_open(
                    From::from(arch),
                    i32::from(kss::Mode::from(mode)),
                    &mut engine,
                )
            };

            if err == kss::Error::KS_ERR_OK {
                Ok(Keystone { engine })
            } else {
                Err(From::from(err))
            }
        }
    }

    pub fn error(&self) -> Result<(), Error> {
        let err = unsafe { kss::ks_errno(self.engine) };

        if err == kss::Error::KS_ERR_OK {
            Ok(())
        } else {
            Err(From::from(err))
        }
    }

    pub fn option(&self, type_: OptionType, value: OptionValue) -> Result<(), Error> {
        let err = unsafe {
            kss::ks_option(
                self.engine,
                From::from(type_),
                i32::from(kss::OptionValue::from(value)) as usize,
            )
        };

        if err == kss::Error::KS_ERR_OK {
            Ok(())
        } else {
            Err(From::from(err))
        }
    }

    pub fn asm(&self, str_: &str, address: u64) -> Result<Assembly, Error> {
        let mut encoding: *mut std::os::raw::c_uchar = std::ptr::null_mut();
        let mut encoding_size: usize = 0;
        let mut stat_count: usize = 0;

        let s = std::ffi::CString::new(str_).unwrap();
        let err = kss::Error::from(unsafe {
            kss::ks_asm(
                self.engine,
                s.as_ptr(),
                address,
                &mut encoding,
                &mut encoding_size,
                &mut stat_count,
            )
        } as u32);

        if err == kss::Error::KS_ERR_OK {
            let bytes = unsafe { std::slice::from_raw_parts(encoding, encoding_size) };

            let ok = Assembly {
                statement_count: stat_count,
                encoding: From::from(&bytes[..]), // copy
            };

            unsafe {
                kss::ks_free(encoding);
            };

            Ok(ok)
        } else {
            let err = unsafe { kss::ks_errno(self.engine) };
            Err(From::from(err))
        }
    }

    pub fn binding_version() -> (u32, u32) {
        (kss::KS_API_MAJOR, kss::KS_API_MINOR)
    }
}

impl Drop for Keystone {
    fn drop(&mut self) {
        unsafe { kss::ks_close(self.engine) };
    }
}

/// Return tuple `(major, minor, extra)` API version numbers.
pub fn version() -> (u32, u32, u32) {
    let mut major: std::os::raw::c_uint = 0;
    let mut minor: std::os::raw::c_uint = 0;

    unsafe {
        kss::ks_version(&mut major, &mut minor);
    }
    (major as u32, minor as u32, kss::KS_VERSION_EXTRA)
}

/// Return whether an arch is supported
pub fn arch_supported(arch: kss::Arch) -> bool {
    unsafe { kss::ks_arch_supported(arch) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amd64() {
        let engine = Keystone::new(Arch::X86, Mode::Bit64).unwrap();

        let asm_result = engine.asm("add rax, rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x48, 0x01, 0xd8]);

        let asm_result = engine.asm("push rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x53]);

        let asm_result = engine.asm("lea rcx, [r12+r9*1-0x01]", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x4b, 0x8d, 0x4c, 0x0c, 0xff]);

        let asm_result = engine.asm("lea rbx, dword ptr [r9+rax*1]", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x49, 0x8d, 0x1c, 0x01]);
    }

    #[test]
    fn test_x86() {
        let engine = Keystone::new(Arch::X86, Mode::Bit32).unwrap();

        let asm_result = engine.asm("xor eax, ebx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x31, 0xd8]);

        let asm_result = engine.asm("sysenter", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x0f, 0x34]);

        let asm_result = engine.asm("repe movsd es:[edi],ds:[esi]", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0xf3, 0xa5]);
    }
}
