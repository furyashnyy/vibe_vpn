use anyhow::{Result, bail};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Keys { pub send: [u8; 32], pub recv: [u8; 32] }

fn proof(key: &[u8; 32], label: &[u8], salt: &[u8; 64]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(label); mac.update(salt);
    let mut out = [0u8; 32]; out.copy_from_slice(&mac.finalize().into_bytes()); out
}
fn verify_proof(key: &[u8; 32], label: &[u8], salt: &[u8;64], candidate: &[u8;32]) -> Result<()> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(label); mac.update(salt);
    mac.verify_slice(candidate).map_err(|_| anyhow::anyhow!("authentication rejected"))
}

/// Authenticated key agreement over a pre-verified TLS 1.3 stream.
/// A password/PSK must be provisioned independently on both ends.
/// HMAC proofs are transcript-bound; directions derive independent AEAD keys.
pub async fn authenticate<S>(stream: &mut S, password: &str, initiator: bool) -> Result<Keys>
where S: AsyncRead + AsyncWrite + Unpin {
    let mut own_nonce = [0u8; 32]; OsRng.fill_bytes(&mut own_nonce);
    let mut peer_nonce = [0u8; 32];
    if initiator {
        stream.write_all(&own_nonce).await?;
        stream.read_exact(&mut peer_nonce).await?;
    } else {
        stream.read_exact(&mut peer_nonce).await?;
        stream.write_all(&own_nonce).await?;
    }
    let mut salt = [0u8; 64];
    if initiator { salt[..32].copy_from_slice(&own_nonce); salt[32..].copy_from_slice(&peer_nonce); }
    else { salt[..32].copy_from_slice(&peer_nonce); salt[32..].copy_from_slice(&own_nonce); }
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut c2s = [0u8;32]; let mut s2c = [0u8;32]; let mut auth = [0u8;32];
    hkdf.expand(b"rustine-v1/c2s", &mut c2s).map_err(|_| anyhow::anyhow!("HKDF expand c2s failed"))?;
    hkdf.expand(b"rustine-v1/s2c", &mut s2c).map_err(|_| anyhow::anyhow!("HKDF expand s2c failed"))?;
    hkdf.expand(b"rustine-v1/auth", &mut auth).map_err(|_| anyhow::anyhow!("HKDF expand auth failed"))?;
    let mut received = [0u8;32];
    if initiator {
        stream.write_all(&proof(&auth, b"client", &salt)).await?;
        stream.read_exact(&mut received).await?;
        verify_proof(&auth, b"server", &salt, &received)?;
        Ok(Keys {send: c2s, recv: s2c})
    } else {
        stream.read_exact(&mut received).await?;
        if verify_proof(&auth, b"client", &salt, &received).is_err() { let _ = stream.shutdown().await; bail!("authentication rejected"); }
        stream.write_all(&proof(&auth, b"server", &salt)).await?;
        Ok(Keys {send: s2c, recv: c2s})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn mutual_auth_keys_are_inverse() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let (x, y) = tokio::join!(authenticate(&mut a, "this-is-a-long-test-password", true), authenticate(&mut b, "this-is-a-long-test-password", false));
        let (x, y) = (x.unwrap(), y.unwrap());
        assert_eq!(x.send, y.recv); assert_eq!(x.recv, y.send); assert_ne!(x.send, x.recv);
    }
    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let (x, y) = tokio::join!(authenticate(&mut a, "client-password-12345", true), authenticate(&mut b, "server-password-12345", false));
        assert!(x.is_err()); assert!(y.is_err());
    }
}
