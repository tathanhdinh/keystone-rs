use keystone_sys as kss;

mod reexport;

pub use crate::reexport::*;
use std::{
    error,
    ffi::{CStr, CString},
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    os::raw,
    ptr, result, slice,
};

type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        use crate::error::Error;
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

// ref: https://stackoverflow.com/questions/41533508/what-is-the-phantomdata-actually-doing-in-the-implementation-of-vec
// PhantomData<'a u8> notifies the compiler that Assembly may own instances of u8!? (NO)
pub struct Assembly<'a> {
    pub statement_count: usize,
    phantom: PhantomData<&'a u8>,
    inner_encoding: &'a [u8],
}

impl<'a> Assembly<'a> {
    pub fn encoding(&self) -> &[u8] {
        self.inner_encoding
    }
}

impl<'a> Drop for Assembly<'a> {
    fn drop(&mut self) {
        unsafe {
            kss::ks_free(self.inner_encoding.as_ptr() as *mut u8)
        };
    }
}

impl<'a> Display for Assembly<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let encoding_strs = self
            .inner_encoding
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
    pub fn from(arch: Arch, mode: Mode) -> Result<Self> {
        let (major, minor, _) = self::version();
        if (major, minor) != Keystone::binding_version() {
            Err(Error::Version)
        } else {
            let mut engine: *mut kss::Engine = ptr::null_mut();
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

    pub fn error(&self) -> Result<()> {
        let err = unsafe { kss::ks_errno(self.engine) };

        if err == kss::Error::KS_ERR_OK {
            Ok(())
        } else {
            Err(From::from(err))
        }
    }

    pub fn option(&self, type_: OptionType, value: OptionValue) -> Result<()> {
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

    pub fn asm<'b>(&self, str_: &'b str, address: u64) -> Result<Assembly> {
        let mut raw_encoding: *mut raw::c_uchar = ptr::null_mut();
        let mut encoding_size: usize = 0;
        let mut statement_count: usize = 0;

        let s = {
            match CString::new(str_) {
                Ok(s) => s,
                Err(err) => CString::new(&str_[0..err.nul_position()]).unwrap(),
            }
        };
        let err = kss::Error::from(unsafe {
            kss::ks_asm(
                self.engine,
                s.as_ptr(),
                address,
                &mut raw_encoding,
                &mut encoding_size,
                &mut statement_count,
            )
        } as u32);

        if err == kss::Error::KS_ERR_OK {
            Ok(Assembly {
                statement_count,
                phantom: PhantomData,
                inner_encoding: unsafe { slice::from_raw_parts(raw_encoding, encoding_size) },
            })
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
        let engine = Keystone::from(Arch::X86, Mode::Bit64);
        assert!(engine.is_ok());

        let engine = engine.unwrap();

        let asm_result = engine.asm("add rax, rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0x48, 0x01, 0xd8]);

        let asm_result = engine.asm("push rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0x53]);

        let asm_result = engine.asm("lea rcx, [r12+r9*1-0x01]", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0x4b, 0x8d, 0x4c, 0x0c, 0xff]);

        // this will not compile
        // let encoding;
        // {
        //     let asm_result = engine.asm("lea rbx, dword ptr [r9+rax*1]", 0x0).unwrap();
        //     encoding = asm_result.encoding();
        // }
        // assert_eq!(encoding, [0x49, 0x8d, 0x1c, 0x01]);

    }

    #[test]
    fn test_x86() {
        let engine = Keystone::from(Arch::X86, Mode::Bit32);
        assert!(engine.is_ok());

        let engine = engine.unwrap();

        let asm_result = engine.asm("xor eax, ebx", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0x31, 0xd8]);

        let asm_result = engine.asm("sysenter", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0x0f, 0x34]);

        let asm_result = engine.asm("repe movsd es:[edi],ds:[esi]", 0x0).unwrap();
        assert_eq!(asm_result.encoding(), [0xf3, 0xa5]);
    }
}
