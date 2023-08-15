use std::fmt::Display;
use std::ops::Deref;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use anyhow::{anyhow, bail};

use crate::jwe::JweContentEncryption;
use crate::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesgcmJweEncryption {
    /// AES GCM using 128-bit key
    A128gcm,
    ///// AES GCM using 192-bit key
    //A192gcm,
    /// AES GCM using 256-bit key
    A256gcm,
}

impl JweContentEncryption for AesgcmJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128gcm => "A128GCM",
            Self::A256gcm => "A256GCM",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128gcm => 16,
            Self::A256gcm => 32,
        }
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
            let nonce = if let Some(iv) = iv {
                iv.into()
            } else {
                bail!("iv is required")
            };

            let mut out = message.to_vec();
            match self {
                Self::A128gcm => {
                    Aes128Gcm::new(key.into()).encrypt_in_place_detached(nonce, aad, &mut out)
                }
                Self::A256gcm => {
                    Aes256Gcm::new(key.into()).encrypt_in_place_detached(nonce, aad, &mut out)
                }
            }
            .map_err(|e| anyhow!(e))
            .map(|tag| (out, Some(tag.to_vec())))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let nonce = if let Some(iv) = iv {
                iv.into()
            } else {
                bail!("iv is required")
            };

            let tag = match tag {
                Some(val) => val.into(),
                None => bail!("A tag value is required."),
            };

            let mut out = encrypted_message.to_vec();
            match self {
                Self::A128gcm => {
                    Aes128Gcm::new(key.into()).decrypt_in_place_detached(nonce, aad, &mut out, tag)
                }
                Self::A256gcm => {
                    Aes256Gcm::new(key.into()).decrypt_in_place_detached(nonce, aad, &mut out, tag)
                }
            }
            .map_err(|e| anyhow!(e))?;

            Ok(out)
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

impl Display for AesgcmJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AesgcmJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::AesgcmJweEncryption;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_aes_gcm() -> Result<()> {
        let message = b"abcde12345";
        let aad = b"test";

        for enc in vec![AesgcmJweEncryption::A128gcm, AesgcmJweEncryption::A256gcm] {
            let key = util::random_bytes(enc.key_len());
            let iv = util::random_bytes(enc.iv_len());

            let (encrypted_message, tag) = enc.encrypt(&key, Some(&iv), message, aad)?;
            let decrypted_message = enc.decrypt(
                &key,
                Some(&iv),
                &encrypted_message,
                &aad[..],
                tag.as_deref(),
            )?;

            assert_eq!(&message[..], &decrypted_message[..]);
        }

        Ok(())
    }
}
