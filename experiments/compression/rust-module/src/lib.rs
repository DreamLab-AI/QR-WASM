//! Benchmark fixture for `experiments/compression`: an RFC 9285 base45 codec
//! exported over a fixed linear-memory buffer, with no imports and no allocator.
#![no_std]

const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const CAP: usize = 4096;

static mut INPUT: [u8; CAP] = [0; CAP];
static mut OUTPUT: [u8; CAP * 2] = [0; CAP * 2];

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[no_mangle]
pub extern "C" fn input_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(INPUT) as *mut u8
}

#[no_mangle]
pub extern "C" fn output_ptr() -> *const u8 {
    core::ptr::addr_of!(OUTPUT) as *const u8
}

/// Encodes `len` bytes of INPUT into OUTPUT; returns the output length or -1.
#[no_mangle]
pub extern "C" fn encode(len: usize) -> isize {
    if len > CAP {
        return -1;
    }
    let (input, output) = unsafe { (&*core::ptr::addr_of!(INPUT), &mut *core::ptr::addr_of_mut!(OUTPUT)) };
    let mut o = 0;
    let mut i = 0;
    while i + 1 < len {
        let mut n = (input[i] as u32) * 256 + input[i + 1] as u32;
        for _ in 0..3 {
            output[o] = ALPHABET[(n % 45) as usize];
            n /= 45;
            o += 1;
        }
        i += 2;
    }
    if i < len {
        let mut n = input[i] as u32;
        for _ in 0..2 {
            output[o] = ALPHABET[(n % 45) as usize];
            n /= 45;
            o += 1;
        }
    }
    o as isize
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Decodes `len` characters of INPUT into OUTPUT; returns the byte length or -1 on invalid input.
#[no_mangle]
pub extern "C" fn decode(len: usize) -> isize {
    if len > CAP || len % 3 == 1 {
        return -1;
    }
    let (input, output) = unsafe { (&*core::ptr::addr_of!(INPUT), &mut *core::ptr::addr_of_mut!(OUTPUT)) };
    let mut o = 0;
    let mut i = 0;
    while i < len {
        let chunk = if len - i >= 3 { 3 } else { 2 };
        let mut n = 0u32;
        let mut scale = 1u32;
        for k in 0..chunk {
            match value(input[i + k]) {
                Some(v) => n += v * scale,
                None => return -1,
            }
            scale *= 45;
        }
        if chunk == 3 {
            if n > 0xFFFF {
                return -1;
            }
            output[o] = (n >> 8) as u8;
            output[o + 1] = n as u8;
            o += 2;
        } else {
            if n > 0xFF {
                return -1;
            }
            output[o] = n as u8;
            o += 1;
        }
        i += chunk;
    }
    o as isize
}

#[cfg(feature = "fmt")]
mod fmt_export {
    use core::fmt::Write;

    struct Cursor<'a> {
        buf: &'a mut [u8],
        at: usize,
    }

    impl Write for Cursor<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.at.checked_add(s.len()).ok_or(core::fmt::Error)?;
            self.buf.get_mut(self.at..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
            self.at = end;
            Ok(())
        }
    }

    /// Writes a human-readable size report for `bytes` into OUTPUT; returns its length or -1.
    #[no_mangle]
    pub extern "C" fn describe(bytes: u64, ratio: f64) -> isize {
        let output = unsafe { &mut *core::ptr::addr_of_mut!(super::OUTPUT) };
        let mut cursor = Cursor { buf: output, at: 0 };
        match write!(cursor, "{bytes} bytes ({:.1} KiB), ratio {ratio:.3}, {:?}", bytes as f64 / 1024.0, (bytes, ratio)) {
            Ok(()) => cursor.at as isize,
            Err(_) => -1,
        }
    }
}
