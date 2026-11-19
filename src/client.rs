use std::{net::{IpAddr,Ipv4Addr,Ipv6Addr}, sync::Arc};
use anyhow::{Context,Result,bail,ensure};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::{TcpListener,TcpStream}};
use tracing::{info,warn};
use crate::{config::Config,peer,protocol::{self,Kind},server};

pub async fn run(cfg:Arc<Config>)->Result<()> {
    let listener=TcpListener::bind(&cfg.listen).await?;
    info!(listen=%cfg.listen,"SOCKS5 + HTTP CONNECT listening");
    loop {
        let (socket,peer_addr)=listener.accept().await?;
        let cfg=cfg.clone();
        tokio::spawn(async move {
            if let Err(e)=handle(socket,&cfg).await {warn!(peer=%peer_addr,error=%e,"proxy connection ended");}
        });
    }
}
async fn handle(mut local:TcpStream,cfg:&Config)->Result<()> {
    let mut peek=[0u8;1];
    tokio::time::timeout(std::time::Duration::from_secs(cfg.connect_timeout_secs),local.peek(&mut peek)).await??;
    let socks=peek[0]==5;
    let (host,port)=tokio::time::timeout(std::time::Duration::from_secs(cfg.connect_timeout_secs),async {
        if socks {parse_socks5(&mut local).await} else {parse_http_connect(&mut local).await}
    }).await.context("local proxy request timeout")??;
    let addr=cfg.relay_addr.as_deref().context("relay_addr missing")?;
    let mut peer=match peer::outgoing(cfg,addr).await {
        Ok(p)=>p,Err(e)=>{report_connect_error(&mut local,socks).await;return Err(e);}
    };
    peer.tx.send(Kind::Connect,&protocol::encode_target(&host,port)?).await?;
    let response=tokio::time::timeout(std::time::Duration::from_secs(cfg.connect_timeout_secs),peer.rx.recv()).await??;
    if response.kind!=Kind::Ok {report_connect_error(&mut local,socks).await;bail!("exit denied CONNECT");}
    if socks {local.write_all(&[5,0,0,1,0,0,0,0,0,0]).await?;}
    else {local.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;}
    let (mut read,mut write)=local.into_split();
    tokio::try_join!(server::plain_to_frames(&mut read,&mut peer.tx),server::frames_to_plain(&mut peer.rx,&mut write))?;
    Ok(())
}
async fn report_connect_error(stream:&mut TcpStream,socks:bool) {
    let bytes: &[u8]=if socks { &[5,1,0,1,0,0,0,0,0,0] } else { b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n" };
    let _=stream.write_all(bytes).await;
}
async fn parse_socks5(stream:&mut TcpStream)->Result<(String,u16)> {
    let mut init=[0u8;2];stream.read_exact(&mut init).await?;
    ensure!(init[0]==5 && init[1]>0,"invalid SOCKS5 greeting");
    let mut methods=vec![0u8;init[1] as usize];stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {stream.write_all(&[5,0xff]).await?;bail!("SOCKS5 no-auth method required");}
    stream.write_all(&[5,0]).await?;
    let mut hdr=[0u8;4];stream.read_exact(&mut hdr).await?;
    ensure!(hdr[0]==5 && hdr[1]==1 && hdr[2]==0,"only SOCKS5 CONNECT supported");
    let host=match hdr[3] {
        1=>{let mut b=[0u8;4];stream.read_exact(&mut b).await?;IpAddr::V4(Ipv4Addr::from(b)).to_string()},
        4=>{let mut b=[0u8;16];stream.read_exact(&mut b).await?;IpAddr::V6(Ipv6Addr::from(b)).to_string()},
        3=>{let len=stream.read_u8().await? as usize;ensure!(len>0,"empty host");let mut b=vec![0u8;len];stream.read_exact(&mut b).await?;String::from_utf8(b)?},
        _=>bail!("unsupported SOCKS5 address type"),
    };
    let port=stream.read_u16().await?;
    ensure!(port>0,"port 0 invalid");
    Ok((host,port))
}
async fn parse_http_connect(stream:&mut TcpStream)->Result<(String,u16)> {
    let mut header=Vec::with_capacity(256);
    loop {
        ensure!(header.len()<8192,"HTTP CONNECT headers too large");
        let b=stream.read_u8().await?; header.push(b);
        if header.ends_with(b"\r\n\r\n") {break;}
    }
    let text=std::str::from_utf8(&header)?;
    let first=text.lines().next().context("missing HTTP CONNECT request")?;
    let mut parts=first.split_ascii_whitespace();
    ensure!(parts.next()==Some("CONNECT"),"only HTTP CONNECT supported");
    let target=parts.next().context("missing CONNECT authority")?;
    let (host,port)=target.rsplit_once(':').context("CONNECT target must be host:port")?;
    let host=host.trim_start_matches('[').trim_end_matches(']');
    let port:u16=port.parse()?;ensure!(!host.is_empty() && port>0,"invalid CONNECT target");
    Ok((host.to_string(),port))
}
