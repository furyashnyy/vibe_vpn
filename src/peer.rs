use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::time::{Duration, timeout};
use crate::{config::Config, crypto, protocol::{Reader, Writer}, tls};

pub struct Peer<S> {
    pub rx: Reader<ReadHalf<S>>,
    pub tx: Writer<WriteHalf<S>>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Peer<S> {
    pub fn new(stream: S, keys: crypto::Keys, cfg: &Config) -> Self {
        let (r,w)=tokio::io::split(stream);
        Self { rx:Reader::new(r,&keys.recv), tx:Writer::new(w,&keys.send,cfg.max_padding,cfg.jitter_ms) }
    }
}
pub async fn outgoing(cfg: &Config, addr: &str) -> Result<Peer<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>> {
    let mut stream=tls::connect(cfg,addr).await?;
    let keys=timeout(Duration::from_secs(cfg.connect_timeout_secs),crypto::authenticate(&mut stream,cfg.secret(),true))
        .await.context("peer authentication timeout")??;
    Ok(Peer::new(stream,keys,cfg))
}
