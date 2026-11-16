//! Sending a group of requests in order (`send --sequence`), as Repeater groups do: each request
//! goes out once the one before it is answered, either all over one keep-alive connection
//! ([`Connections::Single`]: HTTP/1.1, or one HTTP/2 connection) or each over a new connection of
//! its own ([`Connections::Separate`]).
//!
//! Over one HTTP/1.1 connection, what the server sends is read in order: bytes it sent past one
//! response (a desynchronised server, the answer to a request smuggled in a body) are read as the
//! next request's response, which is what a request smuggling test looks for.
//!
//! The sequence stops at the first request that fails, and before a request the one connection
//! can't carry: the server closed it, or said it would, after the request before.

use std::time::Instant;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::auth::AuthSession;
use crate::error::{Error, Result};
use crate::http::client::connection_ends;
use crate::http::h2::{h2_error, setup_error, H2Request};
use crate::http::{Client, Exchange, RawRequest, Stream, Target, WireReader};
use crate::session::Tool;

/// How a sequence's requests are carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connections {
    /// All over one connection, opened for the first request.
    Single,
    /// Each over a new connection, closed once it is answered.
    Separate,
}

impl Connections {
    pub fn name(self) -> &'static str {
        match self {
            Connections::Single => "single",
            Connections::Separate => "separate",
        }
    }
}

/// What [`send_in_order`] reports as it goes, for the caller to record each request.
pub enum Step<'a> {
    /// Request `index` is about to go out: its bytes as recorded (the session applied, auth
    /// placeholders in place of their values, in HTTP/2's text form over HTTP/2).
    Sending(usize, &'a [u8]),
    /// Request `index` is answered.
    Answered(usize, &'a Exchange),
}

/// Why a sequence ended before its last request was answered.
#[derive(Debug)]
pub enum Stop {
    /// Request `at` failed; its result says how. The requests after it weren't sent.
    Failed { at: usize },
    /// Request `next` and those after it weren't sent: the one connection ended after the
    /// request before it, for the reason `why` gives.
    Closed { next: usize, why: String },
}

/// The outcome of [`send_in_order`].
#[derive(Debug)]
pub struct Sequence {
    /// One per request that was sent or tried, in order: the requests after a stop have none.
    pub results: Vec<Result<Exchange>>,
    /// Connections opened.
    pub connections: usize,
    /// Why it ended early, if it did.
    pub stopped: Option<Stop>,
}

/// An open connection: HTTP/1.1 with what is buffered of its next response, or HTTP/2.
enum Conn {
    H1 { stream: Stream, reader: WireReader },
    H2(h2::client::SendRequest<Bytes>),
}

/// Sends `requests` to `target` one after another, each once the one before is answered, over
/// one connection or a new one each (`connections`), over HTTP/2 with `h2`. Every connection goes
/// through `client`, so through the scope guard, the connection options and `--sni`.
///
/// With a `session`, each request gets the session as it is when the request goes out, and its
/// response's cookies are learned, so a cookie an earlier response set goes with later requests.
/// A lost session isn't renewed partway through (that would send a login between two requests).
///
/// `watch` hears of each request just before it goes out and once it is answered; an error from
/// it stops the sequence and is returned, the request it was about left as it was.
pub async fn send_in_order(
    client: &Client,
    session: Option<&AuthSession>,
    target: &Target,
    requests: &[RawRequest],
    connections: Connections,
    h2: bool,
    mut watch: impl FnMut(Step<'_>) -> Result<()>,
) -> Result<Sequence> {
    let timeout = client.options().timeout;
    let mut out = Sequence { results: Vec::new(), connections: 0, stopped: None };
    let mut conn: Option<Conn> = None;
    for (i, given) in requests.iter().enumerate() {
        // An HTTP/2 connection the server has closed (GOAWAY, or gone) is found before anything
        // more is sent on it.
        conn = match conn.take() {
            Some(Conn::H2(sender)) => match sender.ready().await {
                Ok(sender) => Some(Conn::H2(sender)),
                Err(e) => {
                    let why = format!("the server closed the HTTP/2 connection ({})", h2_error(e));
                    out.stopped = Some(Stop::Closed { next: i, why });
                    break;
                }
            },
            other => other,
        };
        let req = match session {
            Some(s) => RawRequest::from_bytes(s.prepare(Tool::Send, target, given.as_bytes(), &[], &[]).await.request),
            None => given.clone(),
        };
        // A request HTTP/2 can't carry fails before anything of it is sent or recorded.
        let recorded = match h2 {
            true => H2Request::from_raw(req.as_bytes(), target).map(|r| r.recorded),
            false => Ok(req.as_bytes().to_vec()),
        };
        let recorded = match recorded {
            Ok(r) => r,
            Err(e) => {
                out.results.push(Err(e));
                out.stopped = Some(Stop::Failed { at: i });
                break;
            }
        };
        watch(Step::Sending(i, &recorded))?;
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        let started = Instant::now();
        let fresh = conn.is_none();
        let opened = &mut out.connections;
        let step = async {
            // What goes on the wire has auth placeholders filled; the row keeps them.
            let filled = client.fill_auth(req.as_bytes(), target).await?;
            client.check_host(&filled, target)?;
            if conn.is_none() {
                conn = Some(open(client, target, h2).await?);
                *opened += 1;
            }
            let response = match conn.as_mut().expect("a connection was opened just above") {
                Conn::H1 { stream, reader } => {
                    stream.write_all(&filled).await?;
                    stream.flush().await?;
                    reader.read_response(stream, &method).await?
                }
                Conn::H2(sender) => {
                    let converted = H2Request::from_raw(&filled, target)?;
                    crate::http::h2::round_trip(sender.clone(), &converted).await?
                }
            };
            Ok::<_, Error>((filled.into_owned(), response))
        };
        let result = tokio::time::timeout(timeout, step).await.map_err(|_| Error::Timeout(timeout)).and_then(|r| r);
        // The first exchange on a new HTTP/2 connection failing usually means the server
        // doesn't speak it: setup_error says so.
        let result = result.map_err(|e| if h2 && fresh { setup_error(target, e) } else { e });
        let (wire, response) = match result {
            Ok(v) => v,
            Err(e) => {
                out.results.push(Err(e));
                out.stopped = Some(Stop::Failed { at: i });
                break;
            }
        };
        let ex = Exchange {
            target: target.clone(),
            request: recorded,
            response,
            duration_ms: started.elapsed().as_millis() as u64,
            sni: client.sni(target),
            stream: None,
        };
        watch(Step::Answered(i, &ex))?;
        if let Some(s) = session {
            s.observe(&ex.response);
        }
        let ends = match (&conn, connections) {
            (Some(Conn::H1 { .. }), Connections::Single) => connection_ends(&wire, &ex.response, &method),
            _ => None,
        };
        out.results.push(Ok(ex));
        if connections == Connections::Separate {
            conn = None;
        }
        if let Some(why) = ends.filter(|_| i + 1 < requests.len()) {
            out.stopped = Some(Stop::Closed { next: i + 1, why: why.to_string() });
            break;
        }
    }
    Ok(out)
}

/// A new connection to `target`: HTTP/2 with `h2` (its driver running on the runtime), else
/// HTTP/1.1.
async fn open(client: &Client, target: &Target, h2: bool) -> Result<Conn> {
    if !h2 {
        return Ok(Conn::H1 { stream: client.connect(target).await?, reader: WireReader::new() });
    }
    let stream = client.connect_h2(target).await?;
    let (sender, connection) = h2::client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(Conn::H2(sender))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::guard::{Guard, ScopeSpec};
    use crate::http::SendOptions;

    fn client(timeout: std::time::Duration) -> Client {
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let guard = Guard::from_specs(vec![scope]).expect("a valid scope");
        Client::new(SendOptions { guard: Some(guard), timeout, ..Default::default() })
    }

    /// An HTTP/1.1 server that answers each request on a connection with `answers[k]` for the
    /// k-th request on it, and closes the connection when that answer is `None`. Returns its
    /// port, the connections it accepted, and every request line it read, in order.
    fn server(answers: Vec<Option<&'static str>>) -> (u16, Arc<AtomicU64>, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (count, seen) = (accepted.clone(), lines.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                let (answers, seen) = (answers.clone(), seen.clone());
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    for answer in answers {
                        let head = loop {
                            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break buf.drain(..at + 4).collect::<Vec<u8>>();
                            }
                            let mut chunk = [0u8; 4096];
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
                        seen.lock().unwrap().push(line);
                        match answer {
                            Some(a) => {
                                let _ = stream.write_all(a.as_bytes());
                            }
                            None => return,
                        }
                    }
                });
            }
        });
        (port, accepted, lines)
    }

    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    fn requests(port: u16, paths: &[&str]) -> Vec<RawRequest> {
        paths
            .iter()
            .map(|p| RawRequest::from_bytes(format!("GET {p} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes()))
            .collect()
    }

    fn target(port: u16) -> Target {
        Target { scheme: "http".into(), host: "127.0.0.1".into(), port }
    }

    #[tokio::test]
    async fn single_sends_in_order_over_one_connection_and_separate_opens_one_each() {
        for (how, want) in [(Connections::Single, 1), (Connections::Separate, 3)] {
            let (port, accepted, lines) = server(vec![Some(OK), Some(OK), Some(OK)]);
            let mut steps = Vec::new();
            let c = client(std::time::Duration::from_secs(5));
            let seq = send_in_order(&c, None, &target(port), &requests(port, &["/a", "/b", "/c"]), how, false, |s| {
                steps.push(match s {
                    Step::Sending(i, _) => format!("sending {i}"),
                    Step::Answered(i, _) => format!("answered {i}"),
                });
                Ok(())
            })
            .await
            .unwrap();
            assert!(seq.stopped.is_none(), "{:?}", seq.stopped);
            assert_eq!(seq.results.len(), 3);
            assert_eq!(seq.connections, want);
            assert_eq!(accepted.load(Ordering::SeqCst), want as u64);
            assert_eq!(*lines.lock().unwrap(), ["GET /a HTTP/1.1", "GET /b HTTP/1.1", "GET /c HTTP/1.1"]);
            assert_eq!(steps, ["sending 0", "answered 0", "sending 1", "answered 1", "sending 2", "answered 2"]);
        }
    }

    #[tokio::test]
    async fn single_stops_when_the_server_says_it_closes_or_just_closes() {
        // Connection: close on the first answer: the second request isn't sent.
        let close = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let (port, accepted, lines) = server(vec![Some(close), Some(OK)]);
        let c = client(std::time::Duration::from_secs(5));
        let seq =
            send_in_order(&c, None, &target(port), &requests(port, &["/a", "/b"]), Connections::Single, false, |_| {
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(seq.results.len(), 1);
        match &seq.stopped {
            Some(Stop::Closed { next: 1, why }) => assert!(why.contains("Connection: close"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(*lines.lock().unwrap(), ["GET /a HTTP/1.1"]);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // The server just closes after the first answer: the second request fails, the third
        // isn't tried.
        let (port, _, _) = server(vec![Some(OK), None]);
        let seq = send_in_order(
            &c,
            None,
            &target(port),
            &requests(port, &["/a", "/b", "/c"]),
            Connections::Single,
            false,
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(seq.results.len(), 2);
        assert!(seq.results[0].is_ok());
        assert!(matches!(seq.stopped, Some(Stop::Failed { at: 1 })), "{:?}", seq.stopped);
        assert!(seq.results[1].is_err());
    }

    #[tokio::test]
    async fn single_reads_extra_bytes_as_the_next_response() {
        // Two responses to the first request (as a desynchronised server sends): the second is
        // read as the answer to the next request, not dropped.
        let two = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nb";
        let (port, _, _) = server(vec![Some(two), Some(OK)]);
        let c = client(std::time::Duration::from_secs(5));
        let seq =
            send_in_order(&c, None, &target(port), &requests(port, &["/a", "/b"]), Connections::Single, false, |_| {
                Ok(())
            })
            .await
            .unwrap();
        let second = seq.results[1].as_ref().unwrap();
        assert!(second.response.starts_with(b"HTTP/1.1 404"), "{}", String::from_utf8_lossy(&second.response));
    }

    #[tokio::test]
    async fn refuses_an_out_of_scope_target_and_stops_when_watch_fails() {
        let c = client(std::time::Duration::from_secs(5));
        let other = Target { scheme: "http".into(), host: "127.0.0.2".into(), port: 9 };
        let seq = send_in_order(&c, None, &other, &requests(9, &["/a", "/b"]), Connections::Single, false, |_| Ok(()))
            .await
            .unwrap();
        assert!(matches!(seq.results[0], Err(Error::OutOfScope(_))), "{:?}", seq.results);
        assert!(matches!(seq.stopped, Some(Stop::Failed { at: 0 })));

        let (port, _, lines) = server(vec![Some(OK), Some(OK)]);
        let err =
            send_in_order(&c, None, &target(port), &requests(port, &["/a", "/b"]), Connections::Single, false, |s| {
                match s {
                    Step::Sending(1, _) => Err(Error::InvalidInput("no room".into())),
                    _ => Ok(()),
                }
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no room"));
        assert_eq!(*lines.lock().unwrap(), ["GET /a HTTP/1.1"]);
    }

    #[tokio::test]
    async fn over_http2_one_connection_carries_every_request() {
        let (port, accepted) = crate::http::h2::tests::h2_server(None).await;
        let c = client(std::time::Duration::from_secs(5));
        let reqs = requests(port, &["/a", "/b", "/c"]);
        let mut recorded = Vec::new();
        let seq = send_in_order(&c, None, &target(port), &reqs, Connections::Single, true, |s| {
            if let Step::Sending(_, r) = s {
                recorded.push(String::from_utf8_lossy(r).lines().next().unwrap_or("").to_string());
            }
            Ok(())
        })
        .await
        .unwrap();
        assert!(seq.stopped.is_none(), "{:?}", seq.stopped);
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        assert_eq!(recorded, ["GET /a HTTP/2", "GET /b HTTP/2", "GET /c HTTP/2"]);
        for (i, p) in ["/a", "/b", "/c"].iter().enumerate() {
            let ex = seq.results[i].as_ref().unwrap();
            assert!(ex.response.ends_with(format!("GET http://127.0.0.1:{port}{p} ").as_bytes()));
        }
        let (port, accepted) = crate::http::h2::tests::h2_server(None).await;
        let seq =
            send_in_order(&c, None, &target(port), &requests(port, &["/a", "/b"]), Connections::Separate, true, |_| {
                Ok(())
            })
            .await
            .unwrap();
        assert!(seq.stopped.is_none());
        assert_eq!((seq.connections, accepted.load(Ordering::Relaxed)), (2, 2));
    }
}
