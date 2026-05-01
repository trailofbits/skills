// Exercises all dangerous API patterns detected by find_dangerous_apis.py.
// All patterns appear within 15 lines of the SecretKey type so that
// has_sensitive_context returns True and confidence = "likely".
use std::mem::{self, ManuallyDrop};
use std::ptr;

struct SecretKey([u8; 32]);

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey([0u8; 32])
    }
}

// B1: mem::forget — prevents Drop from running; secret never zeroed
fn forget_secret(key: SecretKey) {
    mem::forget(key);
}

// B2: ManuallyDrop::new — suppresses automatic drop
fn manual_drop_secret(key: SecretKey) {
    let _md = ManuallyDrop::new(key);
}

// B3: Box::leak — leaked allocation, never dropped or zeroed
fn leak_secret(key: SecretKey) {
    let _: &'static SecretKey = Box::leak(Box::new(key));
}

// B4: mem::uninitialized — may expose prior secret bytes from stack memory
#[allow(deprecated)]
unsafe fn uninit_secret() -> SecretKey {
    mem::uninitialized()
}

// B5: Box::into_raw — raw pointer escapes Drop
fn raw_secret(key: SecretKey) -> *mut SecretKey {
    Box::into_raw(Box::new(key))
}

// B6: ptr::write_bytes — non-volatile, susceptible to dead-store elimination
fn wipe_secret(key: &mut SecretKey) {
    unsafe { ptr::write_bytes(key as *mut SecretKey, 0, 1); }
}

// B7: mem::transmute — bitwise copy of secret bytes
fn transmute_secret(key: SecretKey) -> [u8; 32] {
    unsafe { mem::transmute::<SecretKey, [u8; 32]>(key) }
}

// B8: mem::take — replaces value without zeroing original location
fn take_secret(key: &mut SecretKey) -> SecretKey {
    mem::take(key)
}

// B9: slice::from_raw_parts — aliased reference over secret buffer
fn slice_secret(key: &SecretKey) -> &[u8] {
    unsafe { std::slice::from_raw_parts(key.0.as_ptr(), 32) }
}

async fn noop_op() {}

// B10: async fn with secret local across .await — stored in Future state machine
async fn async_secret() {
    let secret_key = SecretKey([0u8; 32]);
    noop_op().await;
    drop(secret_key);
}
