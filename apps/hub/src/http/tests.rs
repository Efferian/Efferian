#![allow(clippy::unwrap_used, reason = "fixtures and requests must be valid")]

use std::{
    convert::Infallible,
    fs,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Extension,
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
    routing::{any_service, get, post},
};
use bytes::Bytes;
use efferian_protocol::{
    EnrollmentId, GrantId, HubId, NodeId, PrincipalId, PrincipalKind, ProblemDetails, TokenId,
};
use futures_util::StreamExt;
use http::{
    HeaderName, HeaderValue, Method,
    header::{
        ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST,
        IF_NONE_MATCH, ORIGIN, TRANSFER_ENCODING,
    },
};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use rusqlite::params;
use serde::Deserialize;
use tokio::sync::Notify;
use tower_service::Service;
use zeroize::Zeroizing;

use super::*;
use crate::{
    http_transport::ReadIdleTimeout,
    node_bridge::OfflineNodeBridge,
    storage::{
        OpenMode, ShutdownReport, StorageError, StorageRuntime, SystemStorageClock,
        acquire_state_lock, create_staged, open_existing,
    },
    vault::VaultKeys,
};

const HUB: HeaderName = HeaderName::from_static("x-efferian-hub");

struct Fixture {
    state: AppState,
    runtime: StorageRuntime,
    dir: DbDir,
    api: HeaderValue,
    enrollment: HeaderValue,
    node: HeaderValue,
}

struct DbDir(PathBuf);

impl Drop for DbDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let hub_id = HubId::new();
        let dir = DbDir(std::env::temp_dir().join(format!("efferian-http-{hub_id}")));
        let mut config = Config::default();
        config
            .allowed_origins
            .push("https://console.example".parse().unwrap());
        config.max_app_requests = 1;
        config.max_requests_per_principal = 1;
        config.max_control_requests = 1;
        let config = Arc::new(config);
        let storage_config = config.storage_config();
        let clock: Arc<dyn StorageClock> = Arc::new(SystemStorageClock::new().unwrap());
        let keys = VaultKeys::derive(Zeroizing::new([42; 32])).unwrap();
        let identity = keys.new_hub_identity(hub_id);
        let expected = keys.expected_hub_identity();
        let vault = Arc::new(keys.bind_hub(hub_id));
        let admin = PrincipalId::new_for_kind(PrincipalKind::Admin);
        let token = TokenId::new_for_kind(PrincipalKind::Admin);
        let enrollment_id = EnrollmentId::new();
        let node_id = NodeId::new();
        let api = vault.issue_token(token).unwrap();
        let enrollment = vault.issue_enrollment(enrollment_id).unwrap();
        let node = vault.issue_node(node_id).unwrap();
        let now = clock.wall_now_ms();
        let mut lock = acquire_state_lock(&dir.0).unwrap();
        create_staged(&mut lock, identity, &storage_config, clock.as_ref(), |tx| {
            tx.execute(
                "INSERT INTO principals(principal_id, name, kind, created_at_ms, updated_at_ms)
                 VALUES (?1, 'admin', 'admin', ?2, ?2)",
                params![admin.to_string(), now],
            )?;
            tx.execute(
                "INSERT INTO grants(grant_id, principal_id, scope_kind, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'global', 'admin', ?2, ?3)",
                params![GrantId::new().to_string(), admin.to_string(), now],
            )?;
            tx.execute(
                "INSERT INTO auth_tokens(token_id, principal_id, created_by, label, verifier_hmac, created_at_ms)
                 VALUES (?1, ?2, ?2, 'operator', ?3, ?4)",
                params![token.to_string(), admin.to_string(), api.verifier, now],
            )?;
            tx.execute(
                "INSERT INTO node_enrollments(enrollment_id, verifier_hmac, target_node_name, created_by, expires_at_ms, created_at_ms)
                 VALUES (?1, ?2, 'fresh', ?3, ?4, ?5)",
                params![enrollment_id.to_string(), enrollment.verifier, admin.to_string(), now + 60_000, now],
            )?;
            tx.execute(
                "INSERT INTO nodes(node_id, name, credential_hmac, created_at_ms, updated_at_ms)
                 VALUES (?1, 'active', ?2, ?3, ?3)",
                params![node_id.to_string(), node.verifier, now],
            )?;
            Ok::<_, StorageError>(())
        }).unwrap();
        let opened = open_existing(
            lock,
            OpenMode::ServeAutoMigrate,
            expected,
            &storage_config,
            Arc::clone(&clock),
        )
        .unwrap();
        let (storage, runtime) = opened.migrate_and_start_runtime().unwrap();
        let egress = EgressClient::new(config.egress_policy().unwrap()).unwrap();
        let state = AppState {
            storage,
            vault,
            clock,
            config,
            bridge: Arc::new(OfflineNodeBridge),
            egress,
        };
        let bearer = |secret: efferian_protocol::SecretString| {
            let mut value =
                HeaderValue::from_str(&format!("Bearer {}", secret.expose_secret())).unwrap();
            value.set_sensitive(true);
            value
        };
        Self {
            state,
            runtime,
            dir,
            api: bearer(api.secret),
            enrollment: bearer(enrollment.secret),
            node: bearer(node.secret),
        }
    }

    fn router(&self, gate: Arc<Gate>) -> Router {
        assemble(self.state.clone(), 8101, routes_for_tests(gate)).unwrap()
    }

    async fn finish(self) {
        assert!(matches!(
            self.runtime.shutdown().await,
            ShutdownReport::Complete
        ));
        drop(self.dir);
    }
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

struct BlockingClock {
    now: i64,
    entered: Notify,
    released: Mutex<bool>,
    resume: Condvar,
}

impl StorageClock for BlockingClock {
    fn wall_now_ms(&self) -> i64 {
        self.entered.notify_one();
        drop(
            self.resume
                .wait_timeout_while(
                    self.released.lock().unwrap(),
                    Duration::from_secs(5),
                    |released| !*released,
                )
                .unwrap(),
        );
        self.now
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        Ok(Duration::ZERO)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonInput {}

async fn app_json(ApiCaller(_): ApiCaller, ApiJson(_): ApiJson<JsonInput>) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn enrollment_json(
    EnrollmentCaller(_): EnrollmentCaller,
    ApiJson(_): ApiJson<JsonInput>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn node_only(NodeCaller(_): NodeCaller) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn control(ApiCaller(_): ApiCaller, _: EmptyBody) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn hold(Extension(gate): Extension<Arc<Gate>>, ApiCaller(_): ApiCaller) -> StatusCode {
    gate.entered.notify_one();
    gate.release.notified().await;
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryInput {
    mode: String,
}

async fn checked_parameters(
    ApiCaller(_): ApiCaller,
    ApiPath(name): ApiPath<u32>,
    ApiQuery(query): ApiQuery<QueryInput>,
) -> String {
    format!("{name}: {}", query.mode)
}

#[derive(Clone)]
struct FakeMcp;

impl Service<Request> for FakeMcp {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        Box::pin(async move {
            assert!(request.extensions().get::<ApiCaller>().is_some());
            if request.method() == Method::POST {
                assert_eq!(request.body().size_hint().exact(), Some(MCP_LIMIT as u64));
                Ok(StatusCode::NO_CONTENT.into_response())
            } else {
                Ok((
                    StatusCode::METHOD_NOT_ALLOWED,
                    [(ALLOW, HeaderValue::from_static("POST"))],
                )
                    .into_response())
            }
        })
    }
}

fn routes_for_tests(gate: Arc<Gate>) -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::default()
            .route("/v1/test/json", post(app_json))
            .route("/v1/test/params/{id}", get(checked_parameters))
            .route("/v1/test/hold", post(hold).layer(Extension(gate))),
        control: OpenApiRouter::default().route("/v1/test/control", post(control).delete(control)),
        enrollment_api: OpenApiRouter::default().route("/v1/enrollment/tokens", post(app_json)),
        enrollment_exchange: OpenApiRouter::default()
            .route("/v1/enrollment/exchange", post(enrollment_json)),
        node_handshake: OpenApiRouter::default().route("/v1/bridge/connect", get(node_only)),
        mcp: OpenApiRouter::default().route("/mcp/{slug}", any_service(FakeMcp)),
    }
}

fn request(method: Method, path: &str, bearer: Option<&HeaderValue>, body: Body) -> Request {
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, "localhost:8101")
        .body(body)
        .unwrap();
    if let Some(bearer) = bearer {
        request.headers_mut().insert(AUTHORIZATION, bearer.clone());
    }
    request
}

async fn send(mut router: Router, request: Request) -> Response {
    router.call(request).await.unwrap()
}

fn value(raw: &str) -> HeaderValue {
    HeaderValue::from_str(raw).unwrap()
}

async fn problem(response: Response, status: StatusCode, code: &str) -> ProblemDetails {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let problem: ProblemDetails = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.status, status.as_u16());
    assert_eq!(problem.code, code);
    problem
}

fn json_body(size: usize, chunked: bool) -> Body {
    let mut bytes = vec![b' '; size];
    bytes[..2].copy_from_slice(b"{}");
    if chunked {
        // Send the final byte separately to cross the limit mid-stream.
        let last = bytes.pop().unwrap();
        Body::from_stream(futures_util::stream::iter([
            Ok::<_, Infallible>(Bytes::from(bytes)),
            Ok(Bytes::from(vec![last])),
        ]))
    } else {
        Body::from(bytes)
    }
}

fn counted_body() -> (Arc<AtomicUsize>, Body) {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(None::<Result<Bytes, Infallible>>)
    }));
    (calls, body)
}

#[tokio::test]
async fn headers_are_checked_before_credentials_with_health_exception() {
    let fixture = Fixture::new();
    let router = fixture.router(Arc::new(Gate::default()));
    for (path, host, status) in [
        ("/v1/health", "192.0.2.45:8101", StatusCode::OK),
        ("/v1/info", "192.0.2.45:8101", StatusCode::FORBIDDEN),
        ("/v1/openapi.json", "192.0.2.45:8101", StatusCode::FORBIDDEN),
        (
            "/v1/health",
            "person@localhost:8101",
            StatusCode::BAD_REQUEST,
        ),
        ("/v1/info", "localhost:", StatusCode::BAD_REQUEST),
        ("/v1/info", "localhost.:8101", StatusCode::BAD_REQUEST),
        ("/v1/info", "[0::1]:8101", StatusCode::OK),
        (
            "http://LOCALHOST:8101/v1/info",
            "localhost:8101",
            StatusCode::OK,
        ),
        (
            "http://elsewhere:8101/v1/info",
            "localhost:8101",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut req = request(Method::GET, path, None, Body::empty());
        req.headers_mut().insert(HOST, value(host));
        let response = send(router.clone(), req).await;
        assert_eq!(response.status(), status, "{path} with {host}");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
    for (origin, status) in [
        ("HTTPS://CONSOLE.EXAMPLE", StatusCode::OK),
        ("https://console.example/", StatusCode::BAD_REQUEST),
        ("null", StatusCode::FORBIDDEN),
        ("https://attacker.example", StatusCode::FORBIDDEN),
    ] {
        let mut req = request(Method::GET, "/v1/health", None, Body::empty());
        req.headers_mut().insert(ORIGIN, value(origin));
        assert_eq!(send(router.clone(), req).await.status(), status, "{origin}");
    }
    for (name, item) in [
        (HOST, "localhost:8101".to_owned()),
        (ORIGIN, "https://console.example".to_owned()),
        (HUB, fixture.state.storage.hub_id().to_string()),
    ] {
        let mut req = request(Method::GET, "/v1/health", None, Body::empty());
        req.headers_mut().insert(name.clone(), value(&item));
        req.headers_mut().append(name, value(&item));
        problem(
            send(router.clone(), req).await,
            StatusCode::BAD_REQUEST,
            code::INVALID_INPUT,
        )
        .await;
    }
    let (polls, body) = counted_body();
    let mut req = request(Method::POST, "/v1/test/json", None, body);
    req.headers_mut()
        .insert(HUB, value(&HubId::new().to_string()));
    problem(
        send(router.clone(), req).await,
        StatusCode::CONFLICT,
        code::HUB_IDENTITY_MISMATCH,
    )
    .await;
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    let mut req = request(Method::GET, "/v1/health", None, Body::empty());
    req.headers_mut().insert(HUB, value("malformed id"));
    problem(
        send(router, req).await,
        StatusCode::BAD_REQUEST,
        code::INVALID_INPUT,
    )
    .await;
    fixture.finish().await;
}

#[tokio::test]
async fn credentials_and_admission_are_separate_from_body_and_control_routes() {
    let fixture = Fixture::new();
    let gate = Arc::new(Gate::default());
    let router = fixture.router(Arc::clone(&gate));
    let in_progress = tokio::spawn(send(
        router.clone(),
        request(
            Method::POST,
            "/v1/test/hold",
            Some(&fixture.api),
            Body::empty(),
        ),
    ));
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    for bad in [None, Some(&fixture.enrollment), Some(&fixture.node)] {
        let (polls, body) = counted_body();
        let response = send(
            router.clone(),
            request(Method::POST, "/v1/test/json", bad, body),
        )
        .await;
        problem(response, StatusCode::UNAUTHORIZED, code::UNAUTHENTICATED).await;
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }
    let (polls, body) = counted_body();
    let response = send(
        router.clone(),
        request(Method::POST, "/v1/test/json", Some(&fixture.api), body),
    )
    .await;
    assert!(
        problem(response, StatusCode::SERVICE_UNAVAILABLE, code::OVERLOADED)
            .await
            .retryable
    );
    assert_eq!(polls.load(Ordering::Relaxed), 0);

    let res = send(
        router.clone(),
        request(
            Method::POST,
            "/v1/test/control",
            Some(&fixture.api),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = send(
        router.clone(),
        request(Method::GET, "/v1/info", None, Body::empty()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = send(
        router.clone(),
        request(
            Method::GET,
            "/v1/bridge/connect",
            Some(&fixture.node),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    gate.release.notify_one();
    assert_eq!(in_progress.await.unwrap().status(), StatusCode::NO_CONTENT);
    let mut req = request(
        Method::POST,
        "/v1/enrollment/exchange",
        Some(&fixture.enrollment),
        Body::from("{}"),
    );
    req.headers_mut()
        .insert(CONTENT_TYPE, value("application/json"));
    assert_eq!(
        send(router.clone(), req).await.status(),
        StatusCode::NO_CONTENT
    );
    for (method, path, credential) in [
        (Method::GET, "/v1/bridge/connect", &fixture.api),
        (Method::GET, "/v1/bridge/connect", &fixture.enrollment),
        (Method::POST, "/v1/enrollment/exchange", &fixture.api),
        (Method::POST, "/v1/enrollment/exchange", &fixture.node),
    ] {
        let (polls, body) = counted_body();
        let res = send(
            router.clone(),
            request(method, path, Some(credential), body),
        )
        .await;
        problem(res, StatusCode::UNAUTHORIZED, code::UNAUTHENTICATED).await;
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }
    let mut dup = request(
        Method::POST,
        "/v1/test/json",
        Some(&fixture.api),
        Body::empty(),
    );
    dup.headers_mut().append(AUTHORIZATION, fixture.api.clone());
    problem(
        send(router, dup).await,
        StatusCode::UNAUTHORIZED,
        code::UNAUTHENTICATED,
    )
    .await;
    fixture.finish().await;
}

#[tokio::test]
async fn canceled_http_request_keeps_pre_auth_slot_until_sqlite_finishes() {
    let fixture = Fixture::new();
    let mut state = fixture.state.clone();
    Arc::make_mut(&mut state.config).max_pre_auth_in_flight = 1;
    let clock = Arc::new(BlockingClock {
        now: state.clock.wall_now_ms(),
        entered: Notify::new(),
        released: Mutex::new(false),
        resume: Condvar::new(),
    });
    state.clock = clock.clone();
    let router = assemble(state, 8101, routes_for_tests(Arc::new(Gate::default()))).unwrap();
    let authenticating = tokio::spawn(send(
        router.clone(),
        request(
            Method::POST,
            "/v1/test/json",
            Some(&fixture.api),
            Body::empty(),
        ),
    ));
    tokio::time::timeout(Duration::from_secs(2), clock.entered.notified())
        .await
        .unwrap();
    authenticating.abort();
    assert!(authenticating.await.unwrap_err().is_cancelled());

    let (polls, body) = counted_body();
    let protected = send(
        router.clone(),
        request(Method::POST, "/v1/test/control", Some(&fixture.api), body),
    )
    .await;
    let public = send(
        router.clone(),
        request(Method::GET, "/v1/health", None, Body::empty()),
    )
    .await;
    let mut mismatched = request(
        Method::POST,
        "/v1/test/control",
        Some(&fixture.api),
        Body::empty(),
    );
    mismatched
        .headers_mut()
        .insert(HUB, value(&HubId::new().to_string()));
    let mismatch = send(router, mismatched).await;

    *clock.released.lock().unwrap() = true;
    clock.resume.notify_all();
    assert!(
        problem(protected, StatusCode::SERVICE_UNAVAILABLE, code::OVERLOADED)
            .await
            .retryable
    );
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert_eq!(public.status(), StatusCode::OK);
    problem(mismatch, StatusCode::CONFLICT, code::HUB_IDENTITY_MISMATCH).await;
    fixture.finish().await;
}

#[tokio::test]
async fn exact_body_limits_cover_known_lengths_streams_and_mcp() {
    let fixture = Fixture::new();
    let router = fixture.router(Arc::new(Gate::default()));
    for (path, limit, bearer) in [
        ("/v1/test/json", API_LIMIT, &fixture.api),
        ("/v1/enrollment/tokens", ENROLLMENT_LIMIT, &fixture.api),
        (
            "/v1/enrollment/exchange",
            ENROLLMENT_LIMIT,
            &fixture.enrollment,
        ),
        ("/mcp/profile", MCP_LIMIT, &fixture.api),
    ] {
        for chunked in [false, true] {
            for size in [limit, limit + 1] {
                let mut req = request(Method::POST, path, Some(bearer), json_body(size, chunked));
                req.headers_mut()
                    .insert(CONTENT_TYPE, value("application/json"));
                if chunked {
                    req.headers_mut()
                        .insert(TRANSFER_ENCODING, value("chunked"));
                } else {
                    req.headers_mut()
                        .insert(CONTENT_LENGTH, value(&size.to_string()));
                }
                let response = send(router.clone(), req).await;
                if path.starts_with("/mcp/") {
                    assert_eq!(response.headers()["x-accel-buffering"], "no");
                }
                if size <= limit {
                    assert_eq!(
                        response.status(),
                        StatusCode::NO_CONTENT,
                        "{path} at {size}"
                    );
                } else {
                    problem(
                        response,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        code::BODY_TOO_LARGE,
                    )
                    .await;
                }
            }
        }
    }
    for method in [Method::GET, Method::DELETE] {
        let (polls, body) = counted_body();
        let response = send(
            router.clone(),
            request(method, "/mcp/profile", Some(&fixture.api), body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[ALLOW], "POST");
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }
    fixture.finish().await;
}

#[tokio::test]
async fn bodyless_mutations_fail_on_first_byte_and_timeouts_become_problems() {
    let fixture = Fixture::new();
    let router = fixture.router(Arc::new(Gate::default()));
    for method in [Method::POST, Method::DELETE] {
        for length in [1, API_LIMIT + 1] {
            let (polls, body) = counted_body();
            let mut req = request(method.clone(), "/v1/test/control", Some(&fixture.api), body);
            req.headers_mut()
                .insert(CONTENT_LENGTH, value(&length.to_string()));
            let res = send(router.clone(), req).await;
            if length == 1 {
                problem(res, StatusCode::BAD_REQUEST, code::INVALID_INPUT).await;
            } else {
                problem(res, StatusCode::PAYLOAD_TOO_LARGE, code::BODY_TOO_LARGE).await;
            }
            assert_eq!(polls.load(Ordering::Relaxed), 0);
        }
        let body = Body::from_stream(
            futures_util::stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"x")) })
                .chain(futures_util::stream::pending()),
        );
        let mut req = request(method.clone(), "/v1/test/control", Some(&fixture.api), body);
        req.headers_mut()
            .insert(TRANSFER_ENCODING, value("chunked"));
        let response = tokio::time::timeout(Duration::from_secs(5), send(router.clone(), req))
            .await
            .unwrap();
        problem(response, StatusCode::BAD_REQUEST, code::INVALID_INPUT).await;

        let (polls, body) = counted_body();
        let mut req = request(method, "/v1/test/control", Some(&fixture.api), body);
        req.headers_mut()
            .insert(TRANSFER_ENCODING, value("chunked"));
        assert_eq!(
            send(router.clone(), req).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(polls.load(Ordering::Relaxed), 1);
    }

    for path in ["/v1/test/control", "/v1/test/json", "/mcp/profile"] {
        let body = Body::from_stream(futures_util::stream::iter([Err::<Bytes, _>(
            ReadIdleTimeout,
        )]));
        let mut req = request(Method::POST, path, Some(&fixture.api), body);
        req.headers_mut()
            .insert(CONTENT_TYPE, value("application/json"));
        let response = send(router.clone(), req).await;
        assert_eq!(response.headers()[http::header::CONNECTION], "close");
        problem(response, StatusCode::REQUEST_TIMEOUT, code::REQUEST_TIMEOUT).await;
    }
    fixture.finish().await;
}

#[tokio::test]
async fn extractor_failures_and_routing_errors_are_stable_wire_problems() {
    let fixture = Fixture::new();
    let router = fixture.router(Arc::new(Gate::default()));
    for body in ["{", "{\"unknown\":true}"] {
        let mut req = request(
            Method::POST,
            "/v1/test/json",
            Some(&fixture.api),
            Body::from(body),
        );
        req.headers_mut()
            .insert(CONTENT_TYPE, value("application/json"));
        problem(
            send(router.clone(), req).await,
            StatusCode::BAD_REQUEST,
            code::INVALID_INPUT,
        )
        .await;
    }
    let req = request(
        Method::POST,
        "/v1/test/json",
        Some(&fixture.api),
        Body::from("{}"),
    );
    problem(
        send(router.clone(), req).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        code::UNSUPPORTED_MEDIA_TYPE,
    )
    .await;
    for path in [
        "/v1/test/params/invalid?mode=default",
        "/v1/test/params/1?unknown=value",
    ] {
        let req = request(Method::GET, path, Some(&fixture.api), Body::empty());
        problem(
            send(router.clone(), req).await,
            StatusCode::BAD_REQUEST,
            code::INVALID_INPUT,
        )
        .await;
    }
    let res = send(
        router.clone(),
        request(Method::PUT, "/v1/test/control", None, Body::empty()),
    )
    .await;
    let allow = res.headers()[ALLOW].to_str().unwrap();
    assert!(allow.split(',').any(|method| method.trim() == "POST"));
    assert!(allow.split(',').any(|method| method.trim() == "DELETE"));
    problem(
        res,
        StatusCode::METHOD_NOT_ALLOWED,
        code::METHOD_NOT_ALLOWED,
    )
    .await;

    let res = send(
        router,
        request(Method::GET, "/v1/events/stream", None, Body::empty()),
    )
    .await;
    assert_eq!(res.headers()["x-accel-buffering"], "no");
    problem(res, StatusCode::NOT_FOUND, code::NOT_FOUND).await;
    fixture.finish().await;
}

#[tokio::test]
async fn openapi_matches_input_and_boundary_response_contracts() {
    let fixture = Fixture::new();
    let hub = router(fixture.state.clone(), 8101).unwrap();
    let response = send(
        hub,
        request(Method::GET, "/v1/openapi.json", None, Body::empty()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    for (schema, field) in [
        ("MintedToken", "token"),
        ("EnrollmentIssued", "enrollment_token"),
        ("EnrollmentExchanged", "node_token"),
    ] {
        let credential = &doc["components"]["schemas"][schema]["properties"][field];
        assert_eq!(credential["type"], "string");
        assert_eq!(credential["format"], "password");
        assert!(credential.get("writeOnly").is_none());
    }

    let principal_put = &doc["paths"]["/v1/principals/{principal_ref}"]["put"];
    let principal_schema = &principal_put["requestBody"]["content"]["application/json"]["schema"];
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": principal_schema["$ref"].as_str().unwrap(),
        "components": doc["components"],
    });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&serde_json::json!({})));
    assert!(validator.is_valid(&serde_json::json!({"kind": "agent"})));
    assert!(!validator.is_valid(&serde_json::json!({"kind": null})));
    let kind = &doc["components"]["schemas"]["PrincipalPut"]["properties"]["kind"];
    assert!(
        kind["description"]
            .as_str()
            .unwrap()
            .contains("Administrators must supply")
    );

    let ttl = &doc["components"]["schemas"]["MintEnrollment"]["properties"]["ttl_ms"];
    assert!(ttl.get("default").is_none());
    assert_eq!(ttl["minimum"].as_f64(), Some(1.0));
    assert!(
        ttl["description"]
            .as_str()
            .unwrap()
            .contains("orchestrator_enrollment_ttl_ms")
    );

    let paths = &doc["paths"];
    let problem_content = |operation: &serde_json::Value, statuses: &[&str]| {
        for status in statuses {
            assert_eq!(
                operation["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"],
                "#/components/schemas/ProblemDetails",
                "missing problem schema for {} {status}",
                operation["operationId"],
            );
        }
    };
    for path in ["/v1/enrollment/tokens", "/v1/enrollment/exchange"] {
        problem_content(
            &paths[path]["post"],
            &[
                "400", "401", "403", "408", "409", "413", "415", "500", "503",
            ],
        );
    }
    assert!(paths["/v1/enrollment/tokens"]["post"]["responses"]["201"].is_object());
    let bodyless = &paths["/v1/nodes/{id}"]["delete"];
    problem_content(bodyless, &["401", "404", "408", "413", "503"]);
    assert!(bodyless["responses"].get("415").is_none());
    let protected_get = &paths["/v1/nodes/{id}"]["get"];
    problem_content(protected_get, &["400", "401", "404", "503"]);
    for status in ["408", "413", "415"] {
        assert!(protected_get["responses"].get(status).is_none());
    }
    let health = &paths["/v1/health"]["get"];
    problem_content(health, &["400", "403", "409"]);
    assert!(health["responses"].get("401").is_none());
    assert!(health["responses"].get("503").is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn openapi_bytes_are_a_per_router_artifact_with_weak_etag_matching() {
    let fixture = Fixture::new();
    let router = router(fixture.state.clone(), 8101).unwrap();
    let make = || request(Method::GET, "/v1/openapi.json", None, Body::empty());
    let res = send(router.clone(), make()).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[CONTENT_TYPE], "application/json");
    let etag = res.headers()[ETAG].to_str().unwrap().to_owned();
    assert_eq!(etag.len(), 66);
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.last(), Some(&b'\n'));

    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(doc["openapi"].as_str().unwrap().starts_with("3.1."));
    for scheme in ["api_bearer", "enrollment_bearer", "node_bearer"] {
        assert_eq!(
            doc["components"]["securitySchemes"][scheme]["scheme"],
            "bearer"
        );
    }
    assert_eq!(
        doc["paths"]["/v1/health"]["get"]["security"],
        serde_json::json!([])
    );
    assert!(doc["paths"]["/v1/me"]["get"].is_object());
    assert!(doc["paths"]["/v1/enrollment/exchange"]["post"].is_object());
    assert!(doc["paths"]["/mcp/{slug}"].is_null());

    for fields in [
        vec![etag.clone()],
        vec![format!("W/{etag}")],
        vec![format!("\"with,a,comma\", W/{etag}")],
        vec!["\"other\"".to_owned(), format!("W/{etag}")],
        vec!["*".to_owned()],
    ] {
        let mut req = make();
        for field in &fields {
            req.headers_mut().append(IF_NONE_MATCH, value(field));
        }
        let res = send(router.clone(), req).await;
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED, "{fields:?}");
        assert_eq!(res.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(res.headers()[ETAG], etag);
        assert!(
            res.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    let mut req = make();
    req.headers_mut()
        .insert(IF_NONE_MATCH, value("\"unknown\""));
    let res = send(router, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), bytes);
    fixture.finish().await;
}
