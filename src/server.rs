use std::{net::{IpAddr, SocketAddr}, sync::Arc};
use anyhow::{Context, Result, bail, ensure};
use tokio::{io::{AsyncRead,AsyncWrite,AsyncReadExt,AsyncWriteExt}, net::{TcpListener, TcpStream,lookup_host}, sync::Semaphore, time::{Duration,timeout}};
use tracing::{info,warn};
use crate::{config::{Config, Role}, crypto, peer::{self,Peer}, protocol::{self,Kind,Reader,Writer}, tls};

pub async fn run(cfg: Arc<Config>) -> Result<()> {
    let listener=TcpListener::bind(&cfg.listen).await?;
    let acceptor=tls::acceptor(&cfg)?;
    let slots=Arc::new(Semaphore::new(cfg.max_connections));
    info!(role=?cfg.role,listen=%cfg.listen,max_connections=cfg.max_connections,"server ready");
    loop {
        // Acquire BEFORE accept: bounded task count even under unauthenticated floods.
        let permit=slots.clone().acquire_owned().await?;
        let (socket,peer_addr)=listener.accept().await?;
        let acceptor=acceptor.clone(); let cfg=cfg.clone();
        tokio::spawn(async move {
            let _permit=permit;
            let result=async {
                let mut stream=timeout(Duration::from_secs(cfg.connect_timeout_secs),acceptor.accept(socket)).await.context("incoming TLS timeout")??;
                let keys=timeout(Duration::from_secs(cfg.connect_timeout_secs),crypto::authenticate(&mut stream,cfg.secret(),false)).await.context("incoming auth timeout")??;
                let connection=Peer::new(stream,keys,&cfg);
                match cfg.role {
                    Role::Relay=>serve_relay(connection,&cfg).await,
                    Role::Exit=>serve_exit(connection,&cfg).await,
                    Role::Client=>bail!("client cannot accept TLS"),
                }
            }.await;
            if let Err(e)=result { warn!(peer=%peer_addr,error=%e,"connection terminated"); }
        });
    }
}

async fn serve_relay<S:AsyncRead+AsyncWrite+Unpin>(mut incoming:Peer<S>,cfg:&Config)->Result<()> {
    let request=timeout(Duration::from_secs(cfg.connect_timeout_secs),incoming.rx.recv())
        .await.context("CONNECT request timeout")??;
    ensure!(request.kind==Kind::Connect,"expected CONNECT");
    // Relay never connects to the requested destination; it connects only to the pinned EXIT.
    let addr=cfg.next_hop.as_deref().context("next_hop required")?;
    let mut upstream=match peer::outgoing(cfg,addr).await {
        Ok(p)=>p, Err(e)=>{let _=incoming.tx.send(Kind::Error,b"exit unavailable").await; return Err(e);}
    };
    upstream.tx.send(Kind::Connect,&request.data).await?;
    let response=timeout(Duration::from_secs(cfg.connect_timeout_secs),upstream.rx.recv())
        .await.context("upstream CONNECT response timeout")??;
    incoming.tx.send(response.kind,&response.data).await?;
    if response.kind!=Kind::Ok {return Ok(());}
    tokio::try_join!(forward(&mut incoming.rx,&mut upstream.tx),forward(&mut upstream.rx,&mut incoming.tx))?;
    Ok(())
}
async fn forward<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(reader:&mut Reader<R>,writer:&mut Writer<W>)->Result<()> {
    loop { let frame=reader.recv().await?; writer.send(frame.kind,&frame.data).await?; if frame.kind==Kind::End || frame.kind==Kind::Error { return Ok(()); } }
}
async fn serve_exit<S:AsyncRead+AsyncWrite+Unpin>(mut incoming:Peer<S>,cfg:&Config)->Result<()> {
    let request=timeout(Duration::from_secs(cfg.connect_timeout_secs),incoming.rx.recv())
        .await.context("CONNECT request timeout")??;
    ensure!(request.kind==Kind::Connect,"expected CONNECT");
    let (host,port)=protocol::decode_target(&request.data)?;
    let stream=match connect_destination(&host,port,cfg).await {
        Ok(s)=>s, Err(e)=>{
            let _=incoming.tx.send(Kind::Error,b"destination unavailable").await;
            return Err(e);
        }
    };
    incoming.tx.send(Kind::Ok,&[]).await?;
    let (mut remote_read,mut remote_write)=stream.into_split();
    tokio::try_join!(frames_to_plain(&mut incoming.rx,&mut remote_write),plain_to_frames(&mut remote_read,&mut incoming.tx))?;
    Ok(())
}
pub async fn plain_to_frames<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(r:&mut R,w:&mut Writer<W>)->Result<()> {
    let mut buf=[0u8;protocol::MAX_DATA];
    loop {
        let n=r.read(&mut buf).await?;
        if n==0 {w.send(Kind::End,&[]).await?;return Ok(());}
        w.send(Kind::Data,&buf[..n]).await?;
    }
}
pub async fn frames_to_plain<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(r:&mut Reader<R>,w:&mut W)->Result<()> {
    loop {
        let frame=r.recv().await?;
        match frame.kind {
            Kind::Data=>w.write_all(&frame.data).await?,
            Kind::End=>{w.shutdown().await?; return Ok(());},
            Kind::Error=>bail!("remote peer reported error"),
            _=>bail!("unexpected frame after CONNECT"),
        }
    }
}
async fn connect_destination(host:&str,port:u16,cfg:&Config)->Result<TcpStream> {
    let addrs:Vec<SocketAddr>=timeout(Duration::from_secs(cfg.connect_timeout_secs),lookup_host((host,port))).await.context("DNS resolution timeout")??.collect();
    let mut permitted=false;
    for address in addrs {
        if !cfg.allow_private_targets && !is_public(address.ip()) { continue; }
        permitted=true;
        if let Ok(Ok(socket))=timeout(Duration::from_secs(cfg.connect_timeout_secs),TcpStream::connect(address)).await {
            socket.set_nodelay(true)?; return Ok(socket);
        }
    }
    if !permitted { bail!("target is private, reserved or unresolved (set allow_private_targets=true only for trusted environments)"); }
    bail!("no destination address reachable")
}
fn is_public(addr:IpAddr)->bool {
    match addr {
        IpAddr::V4(ip)=>{
            let o=ip.octets();
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || o[0]==0 || o[0]>=240 ||
                (o[0]==100 && (64..=127).contains(&o[1])) || (o[0]==198 && (o[1]==18 || o[1]==19)) ||
                (o[0]==192 && o[1]==0 && o[2]==0) || (o[0]==192 && o[1]==0 && o[2]==2) ||
                (o[0]==198 && o[1]==51 && o[2]==100) || (o[0]==203 && o[1]==0 && o[2]==113))
        },
        IpAddr::V6(ip)=>{
            let b=ip.octets();
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() &&
                !(b[0]&0xfe==0xfc) && !(b[0]==0xfe && (b[1]&0xc0)==0x80) &&
                !(b[0]==0x20 && b[1]==0x01 && b[2]==0x0d && b[3]==0xb8) &&
                !ip.to_ipv4_mapped().is_some_and(|v4|!is_public(IpAddr::V4(v4)))
        }
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn private_destinations_are_filtered() {
        assert!(!is_public(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        assert!(!is_public(IpAddr::V4("10.0.0.4".parse().unwrap())));
        assert!(!is_public(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(is_public(IpAddr::V4("1.1.1.1".parse().unwrap())));
    }

    #[tokio::test]
    async fn idle_post_auth_peer_cannot_hold_slot_forever() {
        let (server_stream, _client_stream) = tokio::io::duplex(64);
        let cfg=Config { role: Role::Exit, connect_timeout_secs: 1, ..Config::default() };
        let peer=Peer::new(server_stream, crypto::Keys { send: [3u8; 32], recv: [4u8; 32] }, &cfg);
        let error=serve_exit(peer,&cfg).await.err().expect("CONNECT should time out");
        assert!(format!("{error:#}").contains("CONNECT request timeout"));
    }
}
