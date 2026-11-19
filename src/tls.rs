use std::{fs::File, io::BufReader, path::Path, sync::Arc};
use anyhow::{Context, Result, ensure};
use tokio::{net::TcpStream, time::{Duration, timeout}};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::{self, ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName}};
use crate::config::Config;

fn certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file=File::open(path).with_context(|| format!("opening certificate {}",path.display()))?;
    let list=rustls_pemfile::certs(&mut BufReader::new(file)).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!list.is_empty(),"empty PEM certificates"); Ok(list)
}
pub fn acceptor(cfg: &Config) -> Result<TlsAcceptor> {
    let cert_path=cfg.cert_path.as_deref().context("cert_path missing")?;
    let key_path=cfg.key_path.as_deref().context("key_path missing")?;
    let key=rustls_pemfile::private_key(&mut BufReader::new(File::open(key_path)?))?.context("no PEM private key")?;
    let conf=ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth().with_single_cert(certs(cert_path)?,key)?;
    Ok(TlsAcceptor::from(Arc::new(conf)))
}
pub fn connector(cfg: &Config) -> Result<TlsConnector> {
    let mut roots=RootCertStore::empty();
    for cert in certs(cfg.ca_path.as_deref().context("ca_path missing")?)? { roots.add(cert)?; }
    let conf=ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots).with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(conf)))
}
pub async fn connect(cfg: &Config, address: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let deadline=Duration::from_secs(cfg.connect_timeout_secs);
    let socket=timeout(deadline,TcpStream::connect(address)).await.context("TCP connect timeout")??;
    socket.set_nodelay(true)?;
    let name=ServerName::try_from(cfg.sni.as_deref().context("SNI missing")?.to_owned())?;
    timeout(deadline,connector(cfg)?.connect(name,socket)).await.context("TLS handshake timeout")?.context("TLS certificate/SNI verification failed")
}
