//! The Hub's HTTP/1 connection admission and idle timeouts.

use std::convert::Infallible;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{Router, body::Body, response::Response};
use bytes::Bytes;
use http::Request;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{self, Sleep};
use tower_service::Service;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BUFFER: usize = 32 * 1024;
const BODY_READ_IDLE: Duration = Duration::from_secs(15);
const BODY_READ_TOTAL: Duration = Duration::from_secs(90);
const WRITE_IDLE: Duration = Duration::from_secs(30);
const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

type IdleTimer = Option<Pin<Box<Sleep>>>;
type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// Stop accepting when `shutdown` resolves, then drain active HTTP connections.
pub async fn serve(
    mut listener: TcpListener,
    router: Router,
    max_tcp_connections: usize,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    if !(1..=Semaphore::MAX_PERMITS).contains(&max_tcp_connections) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid maximum TCP connection count",
        ));
    }
    let permits = Arc::new(Semaphore::new(max_tcp_connections));
    let (drain, _) = watch::channel(());
    let mut tasks = JoinSet::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEADER_BUFFER);
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_err() {
                    tracing::warn!("HTTP connection task stopped unexpectedly");
                }
            }
            (stream, _) = axum::serve::Listener::accept(&mut listener) => {
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(TrackedWriteIdle::new(stream, permit));
                let service = TowerToHyperService::new(ReadIdleService(router.clone()));
                let connection = http.serve_connection(io, service).with_upgrades();
                let mut stopping = drain.subscribe();
                tasks.spawn(async move {
                    tokio::pin!(connection);
                    let result = tokio::select! {
                        biased;
                        _ = stopping.changed() => {
                            connection.as_mut().graceful_shutdown();
                            connection.await
                        }
                        result = &mut connection => result,
                    };
                    if let Err(error) = result {
                        tracing::debug!(timeout = error.is_timeout(), "HTTP connection ended with an error");
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = drain.send(());

    // An upgraded connection owns its socket and permit after the HTTP task returns.
    // The protocol using the upgraded connection is responsible for draining it.
    let joined = time::timeout(HTTP_DRAIN_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if joined.is_err() {
        tracing::warn!("HTTP drain deadline elapsed, closing remaining HTTP connections");
        tasks.shutdown().await;
    }
    Ok(())
}

fn idle_expired(timer: &mut IdleTimer, duration: Duration, cx: &mut Context<'_>) -> bool {
    timer
        .get_or_insert_with(|| Box::pin(time::sleep(duration)))
        .as_mut()
        .poll(cx)
        .is_ready()
}

struct TrackedWriteIdle<S> {
    stream: S,
    write_idle: IdleTimer,
    _permit: OwnedSemaphorePermit,
}

impl<S> TrackedWriteIdle<S> {
    fn new(stream: S, permit: OwnedSemaphorePermit) -> Self {
        Self {
            stream,
            write_idle: None,
            _permit: permit,
        }
    }

    fn track_write(
        &mut self,
        write: Poll<io::Result<usize>>,
        has_data: bool,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        match write {
            Poll::Ready(Ok(written)) if written > 0 => self.write_idle = None,
            Poll::Pending if has_data && idle_expired(&mut self.write_idle, WRITE_IDLE, cx) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP connection stalled while writing",
                )));
            }
            _ => {}
        }
        write
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedWriteIdle<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedWriteIdle<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let write = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.track_write(write, !buf.is_empty(), cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let write = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        let has_data = write.is_pending() && bufs.iter().any(|buf| !buf.is_empty());
        this.track_write(write, has_data, cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Reading a request body stalled within an active read.
#[derive(Debug, thiserror::Error)]
#[error("HTTP request body stalled while reading")]
pub struct ReadIdleTimeout;

struct ReadIdleBody {
    incoming: Incoming,
    read_idle: IdleTimer,
    read_total: IdleTimer,
    timed_out: bool,
}

impl HttpBody for ReadIdleBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(None);
        }
        if idle_expired(&mut this.read_total, BODY_READ_TOTAL, cx) {
            this.timed_out = true;
            this.read_idle = None;
            this.read_total = None;
            return Poll::Ready(Some(Err(ReadIdleTimeout.into())));
        }
        match Pin::new(&mut this.incoming).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    this.read_idle = None;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.read_idle = None;
                this.read_total = None;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                this.read_idle = None;
                this.read_total = None;
                Poll::Ready(None)
            }
            Poll::Pending if idle_expired(&mut this.read_idle, BODY_READ_IDLE, cx) => {
                this.timed_out = true;
                this.read_idle = None;
                this.read_total = None;
                Poll::Ready(Some(Err(ReadIdleTimeout.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.timed_out || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.timed_out {
            SizeHint::with_exact(0)
        } else {
            self.incoming.size_hint()
        }
    }
}

#[derive(Clone)]
struct ReadIdleService(Router);

impl Service<Request<Incoming>> for ReadIdleService {
    type Response = Response;
    type Error = Infallible;
    type Future = <Router as Service<Request<Body>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Router as Service<Request<Body>>>::poll_ready(&mut self.0, cx)
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        self.0.call(request.map(|incoming| {
            Body::new(ReadIdleBody {
                incoming,
                read_idle: None,
                read_total: None,
                timed_out: false,
            })
        }))
    }
}

#[cfg(test)]
mod tests;
