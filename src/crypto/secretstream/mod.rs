//! Stream encryption/file encryption
//!
use ffi::{
    crypto_secretstream_xchacha20poly1305_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push, crypto_secretstream_xchacha20poly1305_keygen,
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_rekey, crypto_secretstream_xchacha20poly1305_state,
};

#[cfg(not(feature = "std"))]
use prelude::*;

use std::marker::PhantomData;
use std::mem;
use std::ptr;

/// A Tag is attached to each message.
#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Tag {
    /// The most common tag, that doesn't add any information about
    /// the nature of the message
    Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8,

    /// Indicates that the message marks the end of a set of messages,
    /// but not the end of the stream.
    Push = crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8,

    /// "Forget" the key used to encrypt this message and the previous ones,
    /// and derive a new secret key.
    Rekey = crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8,

    /// Indicates that the message marks the end of the stream, and erases
    /// the secret key used to encrypt the previous sequence.
    Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8,
}

pub trait StateMode {}

/// Push mode
pub struct Push;

/// Pull mode
pub struct Pull;

impl StateMode for Push {}
impl StateMode for Pull {}

type Header = [u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize];

new_type! {
    /// `Key` for stream encryption
    ///
    /// When a `Key` goes out of scope its contents
    /// will be zeroed out
    secret Key(crypto_secretstream_xchacha20poly1305_KEYBYTES as usize);
}

/// Generates a random key suitable for being used with SecretStream.
pub fn gen_key() -> Key {
    let mut key: [u8; crypto_secretstream_xchacha20poly1305_KEYBYTES as usize] = Default::default();
    unsafe {
        crypto_secretstream_xchacha20poly1305_keygen(key.as_mut_ptr());
    }
    Key(key)
}

/// A secretstream State is a high-level API which encrypts a sequence of messages,
/// or a single message split into an arbitrary number of chunks,
/// using a secret key.
#[derive(Clone)]
pub struct State<T: StateMode> {
    state: crypto_secretstream_xchacha20poly1305_state,
    header: Header,
    phantom: PhantomData<T>,
}

impl State<Pull> {
    /// This method constructs a new SecretStream in Pull mode
    /// (decryption only) with a key `key` and a stream header `header`.
    pub fn init(&Key(ref key): &Key, header: &Header) -> Option<Self> {
        if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
            return None;
        }

        unsafe {
            let mut instance = Self {
                header: Default::default(),
                state: mem::uninitialized(),
                phantom: PhantomData,
            };
            instance.header.copy_from_slice(header);
            crypto_secretstream_xchacha20poly1305_init_pull(
                &mut instance.state as *mut _,
                instance.header.as_mut_ptr(),
                key.as_ptr(),
            );
            Some(instance)
        }
    }

    /// This method verfies that `cipher` contains a valid ciphertext and
    /// valid authentication tag for the current state and optional
    /// authenticated data `ad`.
    ///
    /// If the authentication tag appears to be valid the decrypted
    /// message is put into `out`.
    pub fn pull(&mut self, cipher: &[u8], ad: Option<&[u8]>, out: &mut Vec<u8>) -> Result<Tag, ()> {
        if cipher.len() < crypto_secretstream_xchacha20poly1305_ABYTES as usize {
            return Err(());
        }

        let msg_len = cipher.len() - crypto_secretstream_xchacha20poly1305_ABYTES as usize;
        out.resize(msg_len, 0);

        unsafe {
            let mut tag: Tag = mem::uninitialized();
            if crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state as *mut _,
                out.as_mut_slice().as_mut_ptr(),
                ptr::null_mut(),
                mem::transmute::<_, *mut u8>(&mut tag),
                cipher.as_ptr(),
                cipher.len() as u64,
                ad.map_or(ptr::null(), |x| x.as_ptr()),
                ad.map_or(0, |x| x.len() as u64),
            ) == 0
            {
                return Ok(tag);
            }
        }

        Err(())
    }
}

impl State<Push> {
    /// This method constructs a new SecretStream in Push mode (encryption only)
    /// with a key `key`.
    pub fn init(&Key(ref key): &Key) -> Option<Self> {
        if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
            return None;
        }

        unsafe {
            let mut instance = Self {
                header: Default::default(),
                state: mem::uninitialized(),
                phantom: PhantomData,
            };
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut instance.state as *mut _,
                instance.header.as_mut_ptr(),
                key.as_ptr(),
            );
            Some(instance)
        }
    }

    /// This method encrypts `msg` with the tag `tag` and the state
    /// and puts the cipher code in `out`.
    ///
    /// Additional data can be included in the computation of
    /// the authentication tag by specifying `ad`.
    pub fn push(&mut self, tag: Tag, msg: &[u8], ad: Option<&[u8]>, out: &mut Vec<u8>) {
        let cipher_len = msg.len() + crypto_secretstream_xchacha20poly1305_ABYTES as usize;
        out.resize(cipher_len, 0);

        unsafe {
            crypto_secretstream_xchacha20poly1305_push(
                &mut self.state as *mut _,
                out.as_mut_slice().as_mut_ptr(),
                ptr::null_mut(),
                msg.as_ptr(),
                msg.len() as u64,
                ad.map_or(ptr::null(), |x| x.as_ptr()),
                ad.map_or(0, |x| x.len() as u64),
                tag as u8,
            );
        }
    }
}

impl<T: StateMode> State<T> {
    /// This method returns the stream header.
    pub fn header(&self) -> Header {
        self.header
    }

    /// This method explicitly rekeyes the state without adding a tag or
    /// additional data to the stream.
    ///
    /// Note: If this function is used to create an encrypted stream,
    /// the decryption process must call that function at the exact same
    /// stream location.
    pub fn rekey(&mut self) {
        unsafe {
            crypto_secretstream_xchacha20poly1305_rekey(&mut self.state as *mut _);
        }
    }
}

impl<T: StateMode> Drop for State<T> {
    fn drop(&mut self) {
        use utils::memzero;

        memzero(&mut self.state.k);
        memzero(&mut self.state.nonce);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_push_pull_rekey() {
        // Test stream encryption

        let key = gen_key();

        let mut secret_stream = State::<Push>::init(&key).unwrap();

        let msg1 = "Hello World!";
        let msg2 = "Secret Cipher";
        let msg3 = "Zoop!";

        let mut result1 = Vec::new();
        secret_stream.push(Tag::Message, msg1.as_bytes(), None, &mut result1);

        let mut result2 = Vec::new();
        secret_stream.push(Tag::Message, msg2.as_bytes(), None, &mut result2);

        secret_stream.rekey();

        let mut result3 = Vec::new();
        secret_stream.push(Tag::Final, msg3.as_bytes(), None, &mut result3);

        // Now decrypt the stream

        let header = secret_stream.header();
        let mut secret_stream: State<Pull> = State::<Pull>::init(&key, &header).unwrap();

        let mut plain1 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result1, None, &mut plain1),
            Ok(Tag::Message)
        );
        assert_eq!(plain1.as_slice(), msg1.as_bytes());

        let mut plain2 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result2, None, &mut plain2),
            Ok(Tag::Message)
        );
        assert_eq!(plain2.as_slice(), msg2.as_bytes());

        secret_stream.rekey();

        let mut plain3 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result3, None, &mut plain3),
            Ok(Tag::Final)
        );
        assert_eq!(plain3.as_slice(), msg3.as_bytes());
    }

    #[test]
    fn test_push_pull_rekey_with_ad() {
        let key = gen_key();

        let mut secret_stream = State::<Push>::init(&key).unwrap();

        let msg1 = "Hello World!";
        let msg2 = "Secret Cipher";
        let msg3 = "Zoop!";

        let ad1 = "TestAD1";
        let ad2 = "TestAD22";
        let ad3 = "TestAD333";

        let mut result1 = Vec::new();
        secret_stream.push(
            Tag::Message,
            msg1.as_bytes(),
            Some(ad1.as_bytes()),
            &mut result1,
        );

        let mut result2 = Vec::new();
        secret_stream.push(
            Tag::Message,
            msg2.as_bytes(),
            Some(ad2.as_bytes()),
            &mut result2,
        );

        secret_stream.rekey();

        let mut result3 = Vec::new();
        secret_stream.push(
            Tag::Final,
            msg3.as_bytes(),
            Some(ad3.as_bytes()),
            &mut result3,
        );

        let header = secret_stream.header();
        let mut secret_stream = State::<Pull>::init(&key, &header).unwrap();

        let mut plain1 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result1, Some(ad1.as_bytes()), &mut plain1),
            Ok(Tag::Message)
        );
        assert_eq!(plain1.as_slice(), msg1.as_bytes());

        let mut plain2 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result2, Some(ad2.as_bytes()), &mut plain2),
            Ok(Tag::Message)
        );
        assert_eq!(plain2.as_slice(), msg2.as_bytes());

        secret_stream.rekey();

        let mut plain3 = Vec::new();
        assert_eq!(
            secret_stream.pull(&result3, Some(ad3.as_bytes()), &mut plain3),
            Ok(Tag::Final)
        );
        assert_eq!(plain3.as_slice(), msg3.as_bytes());
    }
}
