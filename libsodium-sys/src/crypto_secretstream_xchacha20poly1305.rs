// crypto_secretstream_xchacha20poly1305.h

pub const crypto_secretstream_xchacha20poly1305_ABYTES: usize = 1 + 16;
pub const crypto_secretstream_xchacha20poly1305_HEADERBYTES: usize = 24;
pub const crypto_secretstream_xchacha20poly1305_KEYBYTES: usize = 32;

pub const crypto_stream_chacha20_ietf_KEYBYTES: usize = 32;
pub const crypto_stream_chacha20_ietf_NONCEBYTES: usize = 12;

pub const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: u8 = 0;
pub const crypto_secretstream_xchacha20poly1305_TAG_PUSH: u8 = 1;
pub const crypto_secretstream_xchacha20poly1305_TAG_REKEY: u8 = 2;
pub const crypto_secretstream_xchacha20poly1305_TAG_FINAL: u8 =
    crypto_secretstream_xchacha20poly1305_TAG_PUSH
        | crypto_secretstream_xchacha20poly1305_TAG_REKEY;

#[repr(C)]
#[derive(Copy)]
pub struct crypto_secretstream_xchacha20poly1305_state {
    pub k: [u8; crypto_stream_chacha20_ietf_KEYBYTES],
    pub nonce: [u8; crypto_stream_chacha20_ietf_NONCEBYTES],
    pub _pad: [u8; 8],
}

impl Clone for crypto_secretstream_xchacha20poly1305_state {
    fn clone(&self) -> crypto_secretstream_xchacha20poly1305_state {
        *self
    }
}

extern "C" {
    pub fn crypto_secretstream_xchacha20poly1305_keygen(key: *mut u8);

    pub fn crypto_secretstream_xchacha20poly1305_init_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *mut u8,
        key: *const u8,
    ) -> i32;

    pub fn crypto_secretstream_xchacha20poly1305_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        c: *mut u8,
        clen_p: *mut u64,
        m: *const u8,
        mlen: u64,
        ad: *const u8,
        adlen: u64,
        tag: u8,
    ) -> i32;

    pub fn crypto_secretstream_xchacha20poly1305_init_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *mut u8,
        key: *const u8,
    ) -> i32;

    pub fn crypto_secretstream_xchacha20poly1305_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        m: *mut u8,
        mlen_p: *mut u64,
        tag_p: *mut u8,
        c: *const u8,
        clen: u64,
        ad: *const u8,
        adlen: u64,
    ) -> i32;

    pub fn crypto_secretstream_xchacha20poly1305_rekey(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
    );
}
