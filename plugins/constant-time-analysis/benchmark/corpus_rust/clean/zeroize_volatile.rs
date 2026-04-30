//! Volatile memzero pattern, equivalent to `zeroize::Zeroize`.
//! No data-dependent operations -- every byte gets the same write
//! regardless of original content.

#![crate_type = "lib"]

#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
    // Memory fence to keep the compiler from reordering the writes.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
pub fn zeroize_u64_array(arr: &mut [u64; 32]) {
    for i in 0..arr.len() {
        unsafe { core::ptr::write_volatile(&mut arr[i], 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
