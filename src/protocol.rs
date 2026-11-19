use anyhow::{Result, bail, ensure};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::obfuscation;

pub const MAX_DATA: usize = 16 * 1024;
const MAX_CIPHERTEXT: usize = MAX_DATA + 4096 + 3 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind { Connect = 1, Ok = 2, Data = 3, End = 4, Error = 5 }
impl TryFrom<u8> for Kind {
    type Error = anyhow::Error;
    fn try_from(v:u8) -> Result<Self> { match v { 1 => Ok(Self::Connect), 2 => Ok(Self::Ok), 3 => Ok(Self::Data), 4 => Ok(Self::End), 5 => Ok(Self::Error), _ => bail!("unknown frame kind") } }
}
pub struct Frame { pub kind: Kind, pub data: Vec<u8> }
fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8;12]; nonce[4..].copy_from_slice(&counter.to_be_bytes()); nonce
}

pub struct Reader<R> { inner: R, cipher: ChaCha20Poly1305, counter: u64 }
pub struct Writer<W> { inner: W, cipher: ChaCha20Poly1305, counter: u64, max_padding: usize, jitter_ms: u64 }
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(inner: R, key: &[u8;32]) -> Self { Self { inner, cipher: ChaCha20Poly1305::new(Key::from_slice(key)), counter: 0 } }
    pub async fn recv(&mut self) -> Result<Frame> {
        let wire_len = self.inner.read_u16().await? as usize;
        ensure!((19..=MAX_CIPHERTEXT).contains(&wire_len), "frame length invalid");
        let mut ciphertext = vec![0u8; wire_len];
        self.inner.read_exact(&mut ciphertext).await?;
        let nonce = nonce_for(self.counter);
        let plaintext = self.cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()).map_err(|_| anyhow::anyhow!("AEAD authentication failed"))?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| anyhow::anyhow!("nonce exhausted"))?;
        ensure!(plaintext.len() >= 3, "short frame");
        let kind = Kind::try_from(plaintext[0])?;
        let payload_len = u16::from_be_bytes([plaintext[1], plaintext[2]]) as usize;
        ensure!(payload_len <= MAX_DATA && 3 + payload_len <= plaintext.len(), "frame payload invalid");
        Ok(Frame { kind, data: plaintext[3..3+payload_len].to_vec() })
    }
}
impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(inner: W, key: &[u8;32], max_padding: usize, jitter_ms: u64) -> Self {
        Self { inner, cipher: ChaCha20Poly1305::new(Key::from_slice(key)), counter:0, max_padding, jitter_ms }
    }
    pub async fn send(&mut self, kind: Kind, data: &[u8]) -> Result<()> {
        ensure!(data.len() <= MAX_DATA, "payload exceeds MAX_DATA");
        let mut plaintext = Vec::with_capacity(3 + data.len() + self.max_padding);
        plaintext.push(kind as u8);
        plaintext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(&obfuscation::random_padding(obfuscation::pad_len(self.max_padding)));
        let nonce = nonce_for(self.counter);
        let ciphertext = self.cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref()).map_err(|_| anyhow::anyhow!("AEAD encrypt failed"))?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| anyhow::anyhow!("nonce exhausted"))?;
        ensure!(ciphertext.len() <= u16::MAX as usize, "ciphertext too large");
        obfuscation::jitter(self.jitter_ms).await;
        self.inner.write_u16(ciphertext.len() as u16).await?;
        self.inner.write_all(&ciphertext).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

pub fn encode_target(host: &str, port: u16) -> Result<Vec<u8>> {
    ensure!(!host.is_empty() && host.len() <= 253 && !host.chars().any(|c| matches!(c, '\0' | '\n' | '\r')), "invalid target hostname");
    ensure!(port > 0, "port 0 invalid");
    let mut data = Vec::with_capacity(host.len()+4);
    data.extend_from_slice(&(host.len() as u16).to_be_bytes());
    data.extend_from_slice(host.as_bytes()); data.extend_from_slice(&port.to_be_bytes());
    Ok(data)
}
pub fn decode_target(data: &[u8]) -> Result<(String, u16)> {
    ensure!(data.len() >= 5, "short CONNECT");
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    ensure!(n > 0 && n <= 253 && data.len() == n+4, "invalid CONNECT length");
    let host = std::str::from_utf8(&data[2..n+2])?.to_owned();
    ensure!(!host.chars().any(|c| matches!(c, '\0' | '\n' | '\r')), "invalid CONNECT host");
    let port = u16::from_be_bytes([data[n+2], data[n+3]]);
    ensure!(port > 0, "port 0 invalid");
    Ok((host,port))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test] async fn frame_roundtrip_and_padding() {
        let (left,right) = tokio::io::duplex(32768);
        let key=[19u8;32];
        let mut w=Writer::new(left,&key,300,0);
        let mut r=Reader::new(right,&key);
        let (x,y)=tokio::join!(w.send(Kind::Data,b"some payload"),r.recv());
        x.unwrap(); let y=y.unwrap(); assert_eq!(y.kind,Kind::Data); assert_eq!(y.data,b"some payload");
    }
    #[tokio::test] async fn wrong_aead_key_rejected() {
        let (left,right)=tokio::io::duplex(4096);
        let mut w=Writer::new(left,&[1u8;32],0,0); let mut r=Reader::new(right,&[2u8;32]);
        let (x,y)=tokio::join!(w.send(Kind::End,b""),r.recv()); x.unwrap(); assert!(y.is_err());
    }
    #[test] fn connect_roundtrip() {
        let b=encode_target("example.com",443).unwrap();
        assert_eq!(decode_target(&b).unwrap(),("example.com".into(),443));
        assert!(encode_target("example.com",0).is_err());
        assert!(encode_target("bad\nname",443).is_err());
        assert!(decode_target(&b[..b.len()-1]).is_err());
    }
    #[tokio::test] async fn ciphertext_tampering_fails() {
        let (tx,rx) = tokio::io::duplex(4096);
        let mut w = Writer::new(tx,&[1u8;32],0,0);
        let mut raw = vec![0u8;32];
        let (sent,received) = tokio::join!(w.send(Kind::Data,b"hello"),async move {
            let mut r=rx;
            r.read_exact(&mut raw[..2]).await.unwrap();
            let n = u16::from_be_bytes([raw[0],raw[1]]) as usize;
            r.read_exact(&mut raw[2..n+2]).await.unwrap();
            raw.truncate(n+2);
            raw[5] ^= 0x80;
            raw
        });
        sent.unwrap();
        let (mut a, b) = tokio::io::duplex(4096);
        let mut reader=Reader::new(b,&[1u8;32]);
        let (written,decoded) = tokio::join!(a.write_all(&received),reader.recv());
        written.unwrap();
        assert!(decoded.unwrap_err().to_string().contains("AEAD"));
    }
    #[tokio::test] async fn independent_frames_in_one_stream() {
        let (left,right)=tokio::io::duplex(65536);
        let mut writer=Writer::new(left,&[77u8;32],20,0);
        let mut reader=Reader::new(right,&[77u8;32]);
        let (send,receive)=tokio::join!(async {
            writer.send(Kind::Data,b"first").await.unwrap();
            writer.send(Kind::End,&[]).await.unwrap();
        },async {
            let a=reader.recv().await.unwrap();
            let b=reader.recv().await.unwrap();
            (a,b)
        });
        let _=send;
        assert_eq!(receive.0.data,b"first");
        assert_eq!(receive.1.kind,Kind::End);
    }
}
