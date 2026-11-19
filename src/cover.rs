//! A real, read-only HTTP/1.1 static website on the tunnel's existing TLS port.
//! Only HTTP requests are dispatched here; tunnel peers retain their original auth flow.
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER: usize = 8192;
const MAX_ASSET: u64 = 2 * 1024 * 1024;

pub fn looks_like_http(prefix: &[u8; 4]) -> bool {
    matches!(prefix, b"GET " | b"HEAD" | b"POST" | b"PUT " | b"OPTI" | b"DELE" | b"PATC" | b"TRAC" | b"CONN")
}

fn mime(file: &Path) -> &'static str {
    match file.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn resolve(root: &Path, url: &str) -> Option<PathBuf> {
    // Forbid URL encodings, backslashes and dot segments, including hidden dotfiles.
    let route = url.split('?').next()?;
    let target = match route {
        "/" => "index.html",
        "/about" => "about.html",
        "/robots.txt" => "robots.txt",
        "/favicon.svg" => "favicon.svg",
        path if path.starts_with("/assets/") => &path[1..],
        _ => return None,
    };
    if !target.split('/').all(|part| !part.is_empty() && !part.starts_with('.') &&
        part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))) { return None; }
    let candidate = root.join(target);
    // canonicalize blocks ../ escapes and symlink escapes even on a writable volume.
    let base = root.canonicalize().ok()?;
    let canonical = candidate.canonicalize().ok()?;
    if canonical.is_file() && canonical.starts_with(base) { Some(canonical) } else { None }
}

async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, status: &str, kind: &str, data: &[u8], head: bool) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCache-Control: public, max-age=120\r\n\r\n",
        data.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if !head { stream.write_all(data).await?; }
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, first: [u8; 4], root: &Path, domain: &str) -> Result<()> {
    let mut request = first.to_vec();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        ensure!(request.len() < MAX_HEADER, "cover request header exceeds limit");
        stream.read_exact(&mut byte).await.context("incomplete HTTP request")?;
        request.push(byte[0]);
    }
    let req = std::str::from_utf8(&request).context("HTTP headers are not UTF-8")?;
    let mut line = req.split("\r\n");
    let first_line = line.next().unwrap_or("");
    let mut parts = first_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return answer(stream,"400 Bad Request","text/plain; charset=utf-8",b"Bad Request\n",false).await;
    }
    let is_head = method == "HEAD";
    if !matches!(method, "GET" | "HEAD") {
        return answer(stream,"405 Method Not Allowed","text/plain; charset=utf-8",b"Method Not Allowed\n",false).await;
    }
    // Require Host to match the operator-owned domain. Never treat arbitrary Host as an open proxy.
    let host = line.filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
        .map(|(_, v)| v.trim().split(':').next().unwrap_or(""))
        .unwrap_or("");
    if !host.eq_ignore_ascii_case(domain) {
        return answer(stream,"421 Misdirected Request","text/plain; charset=utf-8",b"Misdirected Request\n",is_head).await;
    }
    if let Some(file) = resolve(root, path) {
        let meta = tokio::fs::metadata(&file).await?;
        if meta.len() <= MAX_ASSET {
            let bytes = tokio::fs::read(&file).await?;
            return answer(stream,"200 OK",mime(&file),&bytes,is_head).await;
        }
    }
    answer(stream,"404 Not Found","text/plain; charset=utf-8",b"Not Found\n",is_head).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn identify_http_and_not_tunnel_nonces() {
        assert!(looks_like_http(b"GET "));
        assert!(looks_like_http(b"HEAD"));
        assert!(!looks_like_http(&[9, 23, 188, 4]));
    }
    #[test] fn deny_traversal_and_undeclared_paths() {
        let root = Path::new(".");
        assert!(resolve(root,"/../Cargo.toml").is_none());
        assert!(resolve(root,"/%2e%2e/Cargo.toml").is_none());
        assert!(resolve(root,"/.git/config").is_none());
        assert!(resolve(root,"/assets/../Cargo.toml").is_none());
        assert!(resolve(root,"/configs/client.example.toml").is_none());
    }
    async fn test_request(prefix: [u8;4], tail: &'static [u8]) -> String {
        let (mut server, mut client) = tokio::io::duplex(65536);
        let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("cover/site");
        let responder = serve(&mut server, prefix, &site, "relay.test");
        let requester = async move {
            client.write_all(tail).await.unwrap();
            let mut result=Vec::new(); client.read_to_end(&mut result).await.unwrap();
            String::from_utf8(result).unwrap()
        };
        let (status, response)=tokio::join!(responder,requester);
        status.unwrap(); response
    }
    #[tokio::test] async fn website_serves_real_assets() {
        let home=test_request(*b"GET ",b"/ HTTP/1.1\r\nHost: relay.test:443\r\n\r\n").await;
        assert!(home.starts_with("HTTP/1.1 200 OK"));
        assert!(home.contains("FIELDNOTES"));
        let css=test_request(*b"GET ",b"/assets/site.css HTTP/1.1\r\nHost: relay.test\r\n\r\n").await;
        assert!(css.contains("text/css"));
        let missing=test_request(*b"GET ",b"/does-not-exist HTTP/1.1\r\nHost: relay.test\r\n\r\n").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
        let head=test_request(*b"HEAD",b" / HTTP/1.1\r\nHost: relay.test\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(!head.contains("FIELDNOTES"));
    }
    #[tokio::test] async fn website_rejects_unknown_host() {
        let (mut server, mut browser) = tokio::io::duplex(4096);
        let run = serve(&mut server,*b"GET ",Path::new("."),"owned.example");
        let request = async {
            browser.write_all(b"/ HTTP/1.1\r\nHost: wrong.example\r\n\r\n").await.unwrap();
            let mut result = Vec::new(); browser.read_to_end(&mut result).await.unwrap();
            String::from_utf8(result).unwrap()
        };
        let (a, b) = tokio::join!(run, request);
        a.unwrap();
        assert!(b.starts_with("HTTP/1.1 421 "));
    }
}
