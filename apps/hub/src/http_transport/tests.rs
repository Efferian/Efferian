use std::error::Error;
use std::future::{Future, pending};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use http::{StatusCode, header::CONNECTION};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test(start_paused = true)]
async fn write_idle_wakes_a_stalled_writer_at_thirty_seconds() -> TestResult {
    let (stream, _undrained_peer) = tokio::io::duplex(1);
    let permits = Arc::new(Semaphore::new(1));
    let mut io = TrackedWriteIdle::new(stream, permits.acquire_owned().await?);
    io.write_all(b"a").await?;
    let start = time::Instant::now();

    let error = time::timeout(WRITE_IDLE + Duration::from_secs(1), io.write_all(b"b"))
        .await?
        .err()
        .ok_or_else(|| io::Error::other("stalled write did not time out"))?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), WRITE_IDLE);
    Ok(())
}

#[derive(Default)]
struct PartialWriter {
    capacity: usize,
    vectored_calls: usize,
}

impl PartialWriter {
    fn take_capacity(&mut self, offered: usize) -> Poll<io::Result<usize>> {
        let written = offered.min(self.capacity);
        self.capacity -= written;
        if offered != 0 && written == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(written))
        }
    }
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.take_capacity(buf.len())
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.vectored_calls += 1;
        self.take_capacity(bufs.iter().map(|buf| buf.len()).sum())
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn write_idle_tracks_progress_across_scalar_and_vectored_calls() -> TestResult {
    let permits = Arc::new(Semaphore::new(1));
    let mut io = TrackedWriteIdle::new(PartialWriter::default(), permits.acquire_owned().await?);
    let mut cx = Context::from_waker(Waker::noop());
    let vectored = [IoSlice::new(b""), IoSlice::new(b"cd")];
    assert!(io.is_write_vectored());

    // Silence in a handler before its first write is allowed to exceed WRITE_IDLE.
    time::advance(Duration::from_secs(60)).await;
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b""),
        Poll::Ready(Ok(0))
    ));
    assert!(io.write_idle.is_none());
    assert!(Pin::new(&mut io).poll_write(&mut cx, b"ab").is_pending());
    time::advance(Duration::from_secs(29)).await;
    assert!(Pin::new(&mut io).poll_write(&mut cx, b"ab").is_pending());

    io.stream.capacity = 1;
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &vectored),
        Poll::Ready(Ok(1)),
    ));
    assert!(io.write_idle.is_none());
    assert!(
        Pin::new(&mut io)
            .poll_write_vectored(&mut cx, &vectored)
            .is_pending()
    );
    time::advance(Duration::from_secs(29)).await;
    assert!(Pin::new(&mut io).poll_write(&mut cx, b"d").is_pending());
    assert_eq!(io.stream.vectored_calls, 2);

    time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b"d"),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut,
    ));
    Ok(())
}

struct TestServer {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl TestServer {
    async fn start(router: Router, max_tcp_connections: usize) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, router, max_tcp_connections, async {
            let _ = stopped.await;
        }));
        Ok(Self {
            address,
            stop,
            task,
        })
    }

    async fn connect(&self) -> TestResult<TcpStream> {
        Ok(wait_for_io(TcpStream::connect(self.address)).await??)
    }

    async fn stop(self) -> TestResult {
        self.stop
            .send(())
            .map_err(|()| io::Error::other("server exited before stop"))?;
        wait_for_io(self.task).await???;
        Ok(())
    }
}

// Keep the paused clock at the test's chosen point while waiting for loopback I/O.
async fn wait_for_io<F: Future>(future: F) -> io::Result<F::Output> {
    tokio::pin!(future);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Poll::Ready(output) = futures_util::poll!(&mut future) {
            return Ok(output);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "loopback I/O timed out",
            ));
        }
        tokio::task::yield_now().await;
    }
}

async fn head(stream: &mut TcpStream) -> TestResult<String> {
    let bytes = wait_for_io(async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await?);
        }
        Ok::<_, io::Error>(bytes)
    })
    .await??;
    Ok(String::from_utf8(bytes)?)
}

async fn assert_closed(stream: &mut TcpStream) -> TestResult {
    let mut byte = [0];
    let result = wait_for_io(stream.read(&mut byte)).await?;
    assert!(
        matches!(result, Ok(0))
            || matches!(
                result,
                Err(ref error) if error.kind() == io::ErrorKind::ConnectionReset,
            ),
        "connection remained open: {result:?}"
    );
    Ok(())
}

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

#[tokio::test(start_paused = true)]
async fn header_timeout_and_graceful_idle_keep_alive_use_the_real_listener() -> TestResult {
    let server = TestServer::start(
        Router::new().route("/", get(|| async { StatusCode::NO_CONTENT })),
        1,
    )
    .await?;
    let mut incomplete = server.connect().await?;
    wait_for_io(incomplete.write_all(REQUEST)).await??;
    assert!(head(&mut incomplete).await?.starts_with("HTTP/1.1 204"));

    wait_for_io(incomplete.write_all(b"GET / HTTP/1.1\r\nHost:")).await??;
    tokio::task::yield_now().await;
    time::advance(Duration::from_secs(9)).await;
    assert!(
        matches!(incomplete.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    wait_for_io(incomplete.write_all(b" localhost")).await??;
    time::advance(Duration::from_secs(1)).await;
    assert_closed(&mut incomplete).await?;

    let mut keep_alive = server.connect().await?;
    wait_for_io(keep_alive.write_all(REQUEST)).await??;
    assert!(head(&mut keep_alive).await?.starts_with("HTTP/1.1 204"));
    server.stop().await?;
    assert_closed(&mut keep_alive).await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn body_read_idle_is_reset_by_data_and_returns_the_typed_timeout() -> TestResult {
    let (progress, mut seen) = mpsc::unbounded_channel();
    let route = post(move |request: Request<Body>| async move {
        let mut body = request.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        let _ = progress.send(data);
                    }
                }
                Err(error)
                    if error
                        .source()
                        .is_some_and(|source| source.is::<ReadIdleTimeout>()) =>
                {
                    return (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response();
                }
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            }
        }
        StatusCode::NO_CONTENT.into_response()
    });
    let server = TestServer::start(Router::new().route("/", route), 1).await?;
    let mut stream = server.connect().await?;
    wait_for_io(stream.write_all(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
    ))
    .await??;
    assert!(head(&mut stream).await?.starts_with("HTTP/1.1 100"));

    for byte in b"abc" {
        time::advance(Duration::from_secs(14)).await;
        wait_for_io(stream.write_all(&[*byte])).await??;
        assert_eq!(
            wait_for_io(seen.recv()).await?.as_deref(),
            Some(&[*byte][..])
        );
    }
    time::advance(Duration::from_secs(14)).await;
    assert!(
        matches!(stream.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    time::advance(Duration::from_secs(1)).await;
    let response = head(&mut stream).await?;
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert!(response.contains("connection: close\r\n"), "{response}");
    assert_closed(&mut stream).await?;
    server.stop().await
}

#[tokio::test(start_paused = true)]
async fn body_read_total_bounds_slow_trickle_even_with_active_progress() -> TestResult {
    let (progress, mut seen) = mpsc::unbounded_channel();
    let route = post(move |request: Request<Body>| async move {
        let mut body = request.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        let _ = progress.send(data);
                    }
                }
                Err(error)
                    if error
                        .source()
                        .is_some_and(|source| source.is::<ReadIdleTimeout>()) =>
                {
                    return (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response();
                }
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            }
        }
        StatusCode::NO_CONTENT.into_response()
    });
    let server = TestServer::start(Router::new().route("/", route), 1).await?;
    let mut stream = server.connect().await?;
    wait_for_io(stream.write_all(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n",
    ))
    .await??;
    assert!(head(&mut stream).await?.starts_with("HTTP/1.1 100"));

    // Six 14s steps = 84s total, always under the 15s idle window.
    for _ in 0..6 {
        time::advance(Duration::from_secs(14)).await;
        wait_for_io(stream.write_all(b"x")).await??;
        assert_eq!(wait_for_io(seen.recv()).await?.as_deref(), Some(&b"x"[..]));
    }
    // 6s later hits BODY_READ_TOTAL (90s) even though idle is only 6s (< 15s).
    time::advance(Duration::from_secs(6)).await;
    let response = head(&mut stream).await?;
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert!(response.contains("connection: close\r\n"), "{response}");
    assert_closed(&mut stream).await?;
    server.stop().await
}

#[tokio::test(start_paused = true)]
async fn shutdown_bounds_the_drain_of_an_in_flight_request() -> TestResult {
    let (started, mut entered) = mpsc::unbounded_channel();
    let server = TestServer::start(
        Router::new().route(
            "/",
            get(move || async move {
                let _ = started.send(());
                pending::<StatusCode>().await
            }),
        ),
        1,
    )
    .await?;
    let mut stream = server.connect().await?;
    wait_for_io(stream.write_all(REQUEST)).await??;
    assert_eq!(wait_for_io(entered.recv()).await?, Some(()));
    time::advance(WRITE_IDLE + Duration::from_secs(1)).await;
    assert!(
        matches!(stream.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );

    let TestServer { stop, mut task, .. } = server;
    stop.send(())
        .map_err(|()| io::Error::other("server exited before stop"))?;
    assert!(futures_util::poll!(&mut task).is_pending());
    tokio::task::yield_now().await;
    time::advance(HTTP_DRAIN_TIMEOUT - Duration::from_secs(1)).await;
    assert!(futures_util::poll!(&mut task).is_pending());
    time::advance(Duration::from_secs(1)).await;
    wait_for_io(task).await???;
    assert_closed(&mut stream).await
}

#[tokio::test]
async fn upgraded_socket_owns_the_last_tcp_permit_until_closed() -> TestResult {
    let (closed, mut closure) = mpsc::unbounded_channel();
    let router = Router::new()
        .route("/", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/socket",
            get(move |ws: WebSocketUpgrade| async move {
                ws.on_upgrade(move |mut socket| async move {
                    while let Some(Ok(message)) = socket.recv().await {
                        if matches!(message, Message::Close(_)) {
                            break;
                        }
                    }
                    drop(socket);
                    let _ = closed.send(());
                })
            }),
        );
    let server = TestServer::start(router, 1).await?;
    let url = format!("ws://{}/socket", server.address);
    let (mut socket, response) = wait_for_io(tokio_tungstenite::connect_async(url)).await??;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    let mut excess = server.connect().await?;
    assert_closed(&mut excess).await?;

    wait_for_io(socket.close(None)).await??;
    assert_eq!(wait_for_io(closure.recv()).await?, Some(()));
    let mut available = server.connect().await?;
    wait_for_io(available.write_all(REQUEST)).await??;
    assert!(head(&mut available).await?.starts_with("HTTP/1.1 204"));
    server.stop().await
}
