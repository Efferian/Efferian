use std::error::Error;
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{HeaderValue, StatusCode, header::CONTENT_ENCODING};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

use super::*;

const TEST_CA: &[u8] = include_bytes!("fixtures/ca.pem");
const TEST_CERT: &[u8] = include_bytes!("fixtures/upstream.pem");
const TIMEOUT: Duration = Duration::from_secs(3);

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct ScriptedResolver {
    answers: Vec<Vec<SocketAddr>>,
    calls: AtomicUsize,
}

impl ScriptedResolver {
    fn new(answers: Vec<Vec<SocketAddr>>) -> Arc<Self> {
        Arc::new(Self {
            answers,
            calls: AtomicUsize::new(0),
        })
    }
}

impl Resolve for ScriptedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        let answer = self.answers.get(call).cloned();
        Box::pin(async move {
            let answer = answer.ok_or_else(|| io::Error::other("unexpected DNS lookup"))?;
            Ok(Box::new(answer.into_iter()) as Addrs)
        })
    }
}

struct StalledResolver(Arc<Notify>);

impl Resolve for StalledResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        self.0.notify_one();
        Box::pin(pending())
    }
}

fn client(policy: EgressPolicy, resolver: Arc<dyn Resolve>) -> TestResult<EgressClient> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let policy = Arc::new(policy);
    let client = client_builder(Arc::clone(&policy), resolver)
        .add_root_certificate(reqwest::Certificate::from_pem(TEST_CA)?)
        .build()?;
    Ok(EgressClient { client, policy })
}

fn tls_acceptor() -> TestResult<TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from_pem_slice(TEST_CERT)?;
    // RFC 8410 PKCS#8 wrapping the fixed Ed25519 seed used only for this test cert.
    let mut key = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    key.extend([0x42; 32]);
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivatePkcs8KeyDer::from(key).into())?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

async fn read_request(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<String> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    while !request.ends_with("\r\n\r\n") {
        if reader.read_line(&mut request).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no request"));
        }
    }
    Ok(request)
}

async fn get(client: &EgressClient, url: &str) -> Result<Response, EgressError> {
    client.send(Method::GET, url, HeaderMap::new(), None).await
}

fn rejection(error: &EgressError) -> Option<&ResolutionRejected> {
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(rejected) = cause.downcast_ref() {
            return Some(rejected);
        }
        source = cause.source();
    }
    None
}

#[tokio::test]
async fn denied_ip_literal_is_rejected_before_dns() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let dns = ScriptedResolver::new(Vec::new());
    let client = client(EgressPolicy::default(), dns.clone())?;
    let url = format!("https://{}/", listener.local_addr()?);
    let result = tokio::time::timeout(TIMEOUT, get(&client, &url)).await?;
    assert!(matches!(
        result,
        Err(EgressError::Url(SsrfError::DisallowedIp(ip))) if ip.is_loopback()
    ));
    assert_eq!(dns.calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn mixed_and_empty_dns_answers_are_rejected_as_a_whole() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let dns = ScriptedResolver::new(vec![
        vec!["127.0.0.1:0".parse()?, "127.0.0.2:0".parse()?],
        vec![],
    ]);
    let port = listener.local_addr()?.port();
    let policy = EgressPolicy::from_cidrs(&["127.0.0.1/32"], false)?;
    let client = client(policy, dns.clone())?;
    let url = format!("https://upstream.test:{port}/");
    let mixed = tokio::time::timeout(TIMEOUT, get(&client, &url))
        .await?
        .err()
        .ok_or("mixed addresses must fail closed")?;
    assert!(matches!(
        rejection(&mixed),
        Some(ResolutionRejected::Denied)
    ));
    let empty = tokio::time::timeout(TIMEOUT, get(&client, &url))
        .await?
        .err()
        .ok_or("empty addresses must fail closed")?;
    assert!(matches!(rejection(&empty), Some(ResolutionRejected::Empty)));
    assert_eq!(dns.calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn checked_address_preserves_tls_name_and_every_new_connection_is_checked() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = tls_acceptor()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut tls = acceptor.accept(socket).await?;
        let sni = tls.get_ref().1.server_name().map(str::to_owned);
        let headers = read_request(&mut tls).await?;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        tls.shutdown().await?;
        Ok::<_, io::Error>((sni, headers))
    });

    let dns = ScriptedResolver::new(vec![
        vec!["127.0.0.1:0".parse()?],
        vec!["127.0.0.2:0".parse()?],
    ]);
    let policy = EgressPolicy::from_cidrs(&["127.0.0.1/32"], false)?;
    let client = client(policy, dns.clone())?;
    let url = format!("https://upstream.test:{port}/mcp");
    let response = tokio::time::timeout(TIMEOUT, get(&client, &url)).await??;
    assert_eq!(response.bytes().await?, "ok");
    let (sni, request) = server.await??;
    assert_eq!(sni.as_deref(), Some("upstream.test"));
    assert!(request.starts_with("GET /mcp HTTP/1.1\r\n"));
    assert!(request.contains(&format!("host: upstream.test:{port}\r\n")));

    let second = tokio::time::timeout(TIMEOUT, get(&client, &url))
        .await?
        .err()
        .ok_or("the next connection must check fresh DNS results")?;
    assert!(matches!(
        rejection(&second),
        Some(ResolutionRejected::Denied)
    ));
    assert_eq!(dns.calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn trusted_certificate_still_requires_the_requested_hostname() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = tls_acceptor()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        Ok::<_, io::Error>(acceptor.accept(socket).await.is_err())
    });
    let policy = EgressPolicy::from_cidrs(&["127.0.0.1/32"], false)?;
    let dns = ScriptedResolver::new(vec![vec!["127.0.0.1:0".parse()?]]);
    let client = client(policy, dns)?;
    let wrong_name = format!("https://different.test:{port}/");
    let error = tokio::time::timeout(TIMEOUT, get(&client, &wrong_name))
        .await?
        .err()
        .ok_or("TLS name verification must reject SAN mismatch")?;
    assert!(matches!(error, EgressError::Http(ref error) if error.is_connect()));
    assert!(tokio::time::timeout(TIMEOUT, server).await???);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connect_deadline_covers_dns() -> TestResult {
    let started = Arc::new(Notify::new());
    let client = client(
        EgressPolicy::default(),
        Arc::new(StalledResolver(started.clone())),
    )?;
    let request = tokio::spawn(async move { get(&client, "https://upstream.test/").await });
    tokio::time::timeout(Duration::from_secs(1), started.notified()).await?;
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(!request.is_finished());
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = tokio::time::timeout(Duration::from_secs(1), request)
        .await??
        .err()
        .ok_or("connect phase must time out")?;
    assert!(matches!(error, EgressError::Http(ref error) if error.is_timeout()));
    Ok(())
}

#[tokio::test]
async fn authority_override_is_rejected_before_dns() -> TestResult {
    let dns = ScriptedResolver::new(Vec::new());
    let client = client(EgressPolicy::default(), dns.clone())?;
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("other.test"));
    let error = client
        .send(Method::GET, "https://upstream.test/", headers, None)
        .await
        .err()
        .ok_or("Host must be derived from the validated URL")?;
    assert!(matches!(error, EgressError::HostOverride));
    assert_eq!(dns.calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn proxy_environment_is_ignored() -> TestResult {
    // Run in a fresh process because env-based proxy configuration can be cached.
    const CHILD: &str = "EFFERIAN_EGRESS_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0")?;
        let proxy_url = format!("http://{}", proxy.local_addr()?);
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", "egress::tests::proxy_environment_is_ignored"])
            .env(CHILD, "1")
            .env("http_proxy", &proxy_url)
            .env("HTTP_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("no_proxy", "")
            .env("NO_PROXY", "")
            .output()?;
        assert!(
            child.status.success(),
            "proxy test child failed: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
        return Ok(());
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let server = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await?;
                let request = read_request(&mut tcp).await?;
                assert!(request.starts_with("GET /direct HTTP/1.1\r\n"));
                tcp.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
            });
            let dns = ScriptedResolver::new(vec![vec!["127.0.0.1:0".parse()?]]);
            let policy = EgressPolicy::from_cidrs(&["127.0.0.1/32"], true)?;
            let client = client(policy, dns)?;
            let response = tokio::time::timeout(
                TIMEOUT,
                get(&client, &format!("http://upstream.test:{port}/direct")),
            )
            .await??;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            server.await??;
            Ok(())
        })
}

#[tokio::test]
async fn redirect_and_encoded_body_are_returned_unchanged() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    const GZIP: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0xcf, 0x06, 0x00, 0x47,
        0xdd, 0xdc, 0x79, 0x02, 0x00, 0x00, 0x00,
    ];
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await?;
        let _ = read_request(&mut tcp).await?;
        let headers = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://upstream.test:{port}/next\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            GZIP.len()
        );
        tcp.write_all(headers.as_bytes()).await?;
        tcp.write_all(GZIP).await
    });
    let policy = EgressPolicy::from_cidrs(&["127.0.0.1/32"], false)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = EgressClient::new(policy)?;
    let response =
        tokio::time::timeout(TIMEOUT, get(&client, &format!("http://127.0.0.1:{port}/"))).await??;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[CONTENT_ENCODING], "gzip");
    assert_eq!(response.bytes().await?.as_ref(), GZIP);
    server.await??;
    Ok(())
}
