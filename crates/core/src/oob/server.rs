//! The OOB listener: records what targets send to it and answers just enough
//! for clients to send their token (HTTP 200, LDAP bind success, DNS answers
//! with our own address). It never opens outbound connections.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::store::Store;

/// Bytes recorded per interaction.
pub const MAX_RECORD: usize = 16 * 1024;
const CONN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 128;
const HTTP_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub project: PathBuf,
    /// Names under this domain get DNS answers.
    pub domain: Option<String>,
    /// Address returned for A/AAAA queries under the domain.
    pub public_ip: Option<IpAddr>,
}

struct Interaction {
    protocol: &'static str,
    remote: SocketAddr,
    summary: String,
    raw: Vec<u8>,
}

/// Serves until `shutdown` resolves; every interaction is written to the project.
pub async fn serve(
    tcp: TcpListener,
    dns: Option<UdpSocket>,
    opts: ServeOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Interaction>();
    let store = Store::open(&opts.project)?;
    let writer = std::thread::spawn(move || {
        while let Ok(i) = rx.recv() {
            if let Err(e) = store.oob_add_interaction(i.protocol, &i.remote.to_string(), &i.summary, &i.raw) {
                eprintln!("oob: cannot record interaction: {e}");
            }
        }
    });

    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let tcp_loop = {
        let tx = tx.clone();
        async move {
            loop {
                let Ok((stream, remote)) = tcp.accept().await else { continue };
                // Over the limit: drop the connection rather than queue it.
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Some(i) = handle_tcp(stream, remote).await {
                        let _ = tx.send(i);
                    }
                    drop(permit);
                });
            }
        }
    };
    let dns_loop = async {
        let Some(sock) = dns else { return std::future::pending::<()>().await };
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
            if let Some((summary, reply)) = dns_reply(&buf[..n], opts.domain.as_deref(), opts.public_ip) {
                let _ = sock.send_to(&reply, from).await;
                let raw = summary.clone().into_bytes();
                let _ = tx.send(Interaction { protocol: "dns", remote: from, summary, raw });
            }
        }
    };
    tokio::select! {
        _ = shutdown => {}
        _ = tcp_loop => {}
        _ = dns_loop => {}
    }
    drop(tx);
    tokio::task::spawn_blocking(move || writer.join())
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(|_| Error::Protocol("oob writer panicked".into()))
}

/// Reads once into `buf` (up to MAX_RECORD); false on EOF, error, or timeout.
async fn read_more(s: &mut TcpStream, buf: &mut Vec<u8>, deadline: Instant) -> bool {
    let room = MAX_RECORD.saturating_sub(buf.len());
    if room == 0 {
        return false;
    }
    let mut chunk = vec![0u8; room.min(8192)];
    match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
        _ => false,
    }
}

async fn handle_tcp(mut s: TcpStream, remote: SocketAddr) -> Option<Interaction> {
    let deadline = Instant::now() + CONN_TIMEOUT;
    let mut buf = Vec::new();
    if !read_more(&mut s, &mut buf, deadline).await {
        return None;
    }
    let (protocol, summary) = match buf[0] {
        // LDAP (JNDI ldap://): say the bind worked so the client sends its search,
        // whose base DN carries the token.
        0x30 => {
            if let Some(reply) = ldap_bind_reply(&buf) {
                if s.write_all(&reply).await.is_ok() {
                    read_more(&mut s, &mut buf, deadline).await;
                }
            }
            ("ldap", format!("LDAP message ({} bytes)", buf.len()))
        }
        // TLS ClientHello (https:// payloads): the SNI carries the token in DNS mode.
        0x16 => ("tls", format!("TLS ClientHello ({} bytes)", buf.len())),
        b'A'..=b'Z' => {
            while !head_complete(&buf) && read_more(&mut s, &mut buf, deadline).await {}
            let _ = s.write_all(HTTP_REPLY).await;
            let line = buf.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or_default();
            let mut summary = String::from_utf8_lossy(&line[..line.len().min(500)]).into_owned();
            if let Some(host) = header(&buf, "host") {
                summary.push_str(&format!(" (Host: {host})"));
            }
            ("http", summary)
        }
        _ => ("tcp", format!("TCP data ({} bytes)", buf.len())),
    };
    let _ = s.shutdown().await;
    Some(Interaction { protocol, remote, summary, raw: buf })
}

/// True once the head and the Content-Length body (as far as we record) are in.
fn head_complete(buf: &[u8]) -> bool {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return buf.len() >= MAX_RECORD };
    let len: usize = header(buf, "content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    buf.len() >= (end + 4 + len).min(MAX_RECORD)
}

fn header(buf: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    let head = text.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().chars().take(200).collect())
    })
}

/// A BindResponse(success) for the BindRequest in `msg`, echoing its message id.
fn ldap_bind_reply(msg: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE { INTEGER messageID, [APPLICATION 0] BindRequest ... }
    let mut i = 1;
    let len = *msg.get(i)?;
    i += 1 + if len & 0x80 != 0 { (len & 0x7f) as usize } else { 0 };
    if *msg.get(i)? != 0x02 {
        return None;
    }
    let id_len = *msg.get(i + 1)? as usize;
    if id_len == 0 || id_len > 4 {
        return None;
    }
    let id = msg.get(i + 2..i + 2 + id_len)?;
    if *msg.get(i + 2 + id_len)? != 0x60 {
        return None;
    }
    // BindResponse: resultCode success, empty matchedDN and diagnosticMessage.
    let body = [0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
    let mut out = vec![0x30, (2 + id_len + body.len()) as u8, 0x02, id_len as u8];
    out.extend_from_slice(id);
    out.extend_from_slice(&body);
    Some(out)
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// Parses a DNS query; returns "<TYPE> <name>" and the reply: an A/AAAA answer
/// with `ip` for names under `domain`, an empty answer for other types there,
/// REFUSED for everything else.
fn dns_reply(q: &[u8], domain: Option<&str>, ip: Option<IpAddr>) -> Option<(String, Vec<u8>)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let n = *q.get(i)? as usize;
        i += 1;
        if n == 0 {
            break;
        }
        if n > 63 {
            return None;
        }
        labels.push(String::from_utf8_lossy(q.get(i..i + n)?).into_owned());
        i += n;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let qend = i + 4;
    q.get(..qend)?;
    let name = labels.join(".");
    let lower = name.to_ascii_lowercase();
    let ours = domain.is_some_and(|d| {
        let d = d.trim_end_matches('.').to_ascii_lowercase();
        lower == d || lower.ends_with(&format!(".{d}"))
    });
    let rdata: Option<Vec<u8>> = match (ours, qtype, ip) {
        (true, 1, Some(IpAddr::V4(a))) => Some(a.octets().to_vec()),
        (true, 28, Some(IpAddr::V6(a))) => Some(a.octets().to_vec()),
        _ => None,
    };
    let mut r = Vec::with_capacity(qend + 16);
    r.extend_from_slice(&q[..2]);
    // QR, opcode copied, AA, RD copied; rcode 0 or REFUSED.
    r.push(0x80 | (q[2] & 0x78) | 0x04 | (q[2] & 0x01));
    r.push(if ours { 0 } else { 5 });
    r.extend_from_slice(&[0, 1, 0, u8::from(rdata.is_some()), 0, 0, 0, 0]);
    r.extend_from_slice(&q[12..qend]);
    if let Some(d) = rdata {
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&qtype.to_be_bytes());
        r.extend_from_slice(&[0, 1, 0, 0, 0, 0]); // class IN, TTL 0
        r.extend_from_slice(&(d.len() as u16).to_be_bytes());
        r.extend_from_slice(&d);
    }
    Some((format!("{} {name}", qtype_name(qtype)), r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn dns_answers_only_our_domain() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let q = query("BPabc.Oob.Test", 1);
        let (summary, r) = dns_reply(&q, Some("oob.test"), Some(ip)).unwrap();
        assert_eq!(summary, "A BPabc.Oob.Test");
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80); // response
        assert_eq!(r[3] & 0x0f, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1); // one answer
        assert_eq!(&r[r.len() - 4..], &[203, 0, 113, 5]);
        // AAAA under our domain without a v6 address: empty NOERROR.
        let (_, r) = dns_reply(&query("x.oob.test", 28), Some("oob.test"), Some(ip)).unwrap();
        assert_eq!((r[3] & 0x0f, r[7]), (0, 0));
        // Someone else's name: REFUSED, still recorded.
        let (summary, r) = dns_reply(&query("example.com", 1), Some("oob.test"), Some(ip)).unwrap();
        assert_eq!(summary, "A example.com");
        assert_eq!((r[3] & 0x0f, r[7]), (5, 0));
        // Not a query / truncated.
        let mut resp = q.clone();
        resp[2] |= 0x80;
        assert!(dns_reply(&resp, Some("oob.test"), Some(ip)).is_none());
        assert!(dns_reply(&q[..q.len() - 3], Some("oob.test"), Some(ip)).is_none());
    }

    #[test]
    fn ldap_bind_reply_echoes_message_id() {
        // BindRequest, id 1, version 3, empty name, simple auth "".
        let bind = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00];
        let r = ldap_bind_reply(&bind).unwrap();
        assert_eq!(r, vec![0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]);
        assert!(ldap_bind_reply(&[0x30, 0x03, 0x04, 0x01, 0x00]).is_none());
    }

    #[test]
    fn http_head_completion() {
        assert!(!head_complete(b"GET / HTTP/1.1\r\nHost: a\r\n"));
        assert!(head_complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(!head_complete(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"));
        assert!(head_complete(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde"));
        assert_eq!(header(b"GET / HTTP/1.1\r\nHOST: x.test\r\n\r\n", "host").as_deref(), Some("x.test"));
    }

    #[tokio::test]
    async fn records_http_ldap_and_dns() {
        let dir = std::env::temp_dir().join(format!("bp-oob-srv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        let store = Store::open(&project).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tcp_addr, udp_addr) = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
        let opts = ServeOptions {
            project: project.clone(),
            domain: Some("oob.test".into()),
            public_ip: Some("127.0.0.1".parse().unwrap()),
        };
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(tcp, Some(udp), opts, async {
            let _ = stop_rx.await;
        }));
        let tok = crate::oob::new_token().unwrap();

        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        s.write_all(format!("GET /{tok} HTTP/1.1\r\nHost: cb.test\r\n\r\n").as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));

        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        s.write_all(&[0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00])
            .await
            .unwrap();
        let mut reply = [0u8; 14];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[5], 0x61);
        let mut search = vec![0x30, 0x20, 0x02, 0x01, 0x02, 0x63, 0x1b, 0x04, 0x14];
        search.extend_from_slice(tok.as_bytes());
        s.write_all(&search).await.unwrap();
        drop(s);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query(&format!("{tok}.oob.test"), 1), udp_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);

        // Wait for all three to be written.
        let deadline = Instant::now() + Duration::from_secs(10);
        let rows = loop {
            let rows = store.oob_interactions(0, Some(&tok), 10, 1000).unwrap();
            if rows.len() >= 3 || Instant::now() > deadline {
                break rows;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let protos: Vec<&str> = rows.iter().map(|r| r["protocol"].as_str().unwrap()).collect();
        assert!(protos.contains(&"http") && protos.contains(&"ldap") && protos.contains(&"dns"), "{rows:?}");
        let http = rows.iter().find(|r| r["protocol"] == "http").unwrap();
        assert_eq!(http["summary"], format!("GET /{tok} HTTP/1.1 (Host: cb.test)"));
        let _ = stop_tx.send(());
        server.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
