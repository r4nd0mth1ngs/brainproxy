//! Race-condition sending with last-byte synchronisation: open every connection
//! (TLS included) and send all but the final byte of each request, then release
//! the final bytes together so the server receives the requests at nearly the
//! same moment. Works over HTTP/1.1 against any server.

use std::time::Instant;

use tokio::io::AsyncWriteExt;

use crate::error::{Error, Result};
use crate::http::{Client, Exchange, Target, WireReader};

/// Sends `requests` concurrently. Results are in the same order as `requests`;
/// `duration_ms` is measured from the moment the final bytes were released.
pub async fn last_byte_sync(client: &Client, target: &Target, requests: Vec<Vec<u8>>) -> Vec<Result<Exchange>> {
    // 1. Connect everything up front.
    let mut connects = Vec::new();
    for _ in &requests {
        let (client, target) = (client.clone(), target.clone());
        connects.push(tokio::spawn(async move { client.connect(&target).await }));
    }
    let mut streams = Vec::new();
    for c in connects {
        streams.push(c.await.map_err(|e| Error::Protocol(e.to_string())).and_then(|r| r));
    }

    // 2. Send everything except the last byte.
    for (stream, req) in streams.iter_mut().zip(&requests) {
        if let Ok(s) = stream {
            let body = &req[..req.len().saturating_sub(1)];
            if let Err(e) = async {
                s.write_all(body).await?;
                s.flush().await
            }
            .await
            {
                *stream = Err(e.into());
            }
        }
    }

    // 3. Release the last bytes back to back.
    let released = Instant::now();
    for (stream, req) in streams.iter_mut().zip(&requests) {
        if let Ok(s) = stream {
            if let Err(e) = async {
                s.write_all(&req[req.len().saturating_sub(1)..]).await?;
                s.flush().await
            }
            .await
            {
                *stream = Err(e.into());
            }
        }
    }

    // 4. Read the responses concurrently.
    let mut reads = Vec::new();
    for (stream, req) in streams.into_iter().zip(requests) {
        let target = target.clone();
        reads.push(tokio::spawn(async move {
            let mut s = stream?;
            let method = crate::http::RawRequest::from_bytes(req.clone()).head().map(|h| h.method).unwrap_or_default();
            let response = WireReader::new().read_response(&mut s, &method).await?;
            Ok(Exchange { target, request: req, response, duration_ms: released.elapsed().as_millis() as u64 })
        }));
    }
    let mut out = Vec::new();
    for r in reads {
        out.push(r.await.map_err(|e| Error::Protocol(e.to_string())).and_then(|r| r));
    }
    out
}
