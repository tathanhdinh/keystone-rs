pub mod gen;

pub fn binding_version() -> (u32, u32) {
    (gen::KS_API_MAJOR, gen::KS_API_MINOR)
}

/// Return tuple `(major, minor)` API version numbers.
pub fn version() -> (u32, u32) {
    let mut major: std::os::raw::c_uint = 0;
    let mut minor: std::os::raw::c_uint = 0;

    unsafe {
        gen::ks_version(&mut major, &mut minor);
    }
    (major as u32, minor as u32)
}

/// Return whether an arch is supported
pub fn arch_supported(arch: gen::ks_arch) -> bool {
    unsafe {
        gen::ks_arch_supported(arch)
    }
}

#[derive(Debug)]
pub struct Error {
    pub err: gen::ks_err,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let err_msg = unsafe {
            std::ffi::CStr::from_ptr(gen::ks_strerror(self.err))
        };
        write!(f, "{}", err_msg.to_str().unwrap())
    }
}

pub struct AsmResult {
    pub stat_count: usize,
    pub encoding: Vec<u8>,
}

impl std::fmt::Display for AsmResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let encoding_strs = self.encoding
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        // try!(f.write_fmt(format_args!("{}", encoding_strs)));
        write!(f, "{}", encoding_strs)
        // Ok(())
    }
}

pub struct Keystone {
    engine: *mut gen::ks_engine,
}

impl Keystone {
    /// Create new instance of Keystone engine.
    pub fn new(arch: gen::ks_arch, mode: gen::ks_mode) -> Result<Keystone, Error> {
        if version() != binding_version() {
            Err(Error { err: gen::KS_ERR_VERSION })
        }
        else {
            let mut engine: *mut gen::ks_engine = std::ptr::null_mut();
            let err = unsafe {
                gen::ks_open(arch, mode, &mut engine)
            };
            
            if err == gen::KS_ERR_OK {
                Ok(Keystone { engine: engine })
            }
            else {
                Err(Error { err: err })
            }
        }
    }

    pub fn error(&self) -> Result<(), Error> {
        let err = unsafe {
            gen::ks_errno(self.engine)
        };

        if err == gen::KS_ERR_OK {
            Ok(())
        }
        else {
            Err(Error { err: err })
        }
    }

    pub fn option(&self, type_: gen::ks_opt_type, value: gen::ks_opt_value) -> Result<(), Error> {
        let err = unsafe {
            gen::ks_option(self.engine, type_, value as usize)
        };

        if err == gen::KS_ERR_OK {
            Ok(())
        }
        else {
            Err(Error { err: err })
        }
    }

    pub fn asm(&self, str_: &str, address: u64) -> Result<AsmResult, Error> {
        let mut encoding: *mut std::os::raw::c_uchar = std::ptr::null_mut();
        let mut encoding_size: usize = 0;
        let mut stat_count: usize = 0;

        let s = std::ffi::CString::new(str_).unwrap();
        let err = unsafe {
            gen::ks_asm(self.engine, s.as_ptr(), address, 
                        &mut encoding, &mut encoding_size, &mut stat_count)
        } as gen::ks_err;

        if err == gen::KS_ERR_OK {
            let bytes = unsafe {
                std::slice::from_raw_parts(encoding, encoding_size)
            };

            let ok = AsmResult {
                stat_count: stat_count,
                encoding: From::from(&bytes[..]), // copy
            };

            unsafe {
                gen::ks_free(encoding);
            };

            Ok(ok)
        }
        else {
            let err = unsafe {
                gen::ks_errno(self.engine)
            };
            Err(Error { err: err })
        }
    }
}

impl Drop for Keystone {
    fn drop(&mut self) {
        unsafe {
            gen::ks_close(self.engine)
        };
    }
}

#[cfg(test)]
mod tests {
    use gen::*;
    use super::*;

    #[test]
    fn test_amd64() {
        let engine = Keystone::new(KS_ARCH_X86, KS_MODE_64).unwrap();

        let asm_result = engine.asm("add rax, rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x48, 0x01, 0xd8]);

        let asm_result = engine.asm("push rbx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x53]);

        let asm_result = engine.asm("lea rcx, [r12+r9*1-0x01]", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x4b, 0x8d, 0x4c, 0x0c, 0xff]);
    }

    #[test]
    fn test_x86() {
        let engine = Keystone::new(KS_ARCH_X86, KS_MODE_32).unwrap();

        let asm_result = engine.asm("xor eax, ebx", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x31, 0xd8]);

        let asm_result = engine.asm("sysenter", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0x0f, 0x34]);

        let asm_result = engine.asm("repe movsd es:[edi],ds:[esi]", 0x0).unwrap();
        assert_eq!(asm_result.encoding[..], [0xf3, 0xa5]);
    }
}
