use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use futures_util::{StreamExt, stream::BoxStream};
use reqwest::header::{HeaderName, HeaderValue};
use rmcp::{
    model::{ClientJsonRpcMessage, ClientRequest, PingRequest, RequestId, ServerJsonRpcMessage},
    transport::{
        Transport,
        streamable_http_client::{
            SseError, StreamableHttpClient, StreamableHttpClientTransport,
            StreamableHttpClientTransportConfig, StreamableHttpError, StreamableHttpPostResponse,
            StreamableHttpResponseLimits,
        },
    },
};
use sse_stream::{Sse, SseStream};

type Headers = HashMap<HeaderName, HeaderValue>;
type Events = BoxStream<'static, Result<Sse, SseError>>;
type AdapterResult<T> = Result<T, StreamableHttpError<reqwest::Error>>;

fn ping_response() -> StreamableHttpPostResponse {
    let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
    let response = reqwest::Response::from(axum::http::Response::new(body));
    let events = SseStream::from_bytes_stream(response.bytes_stream()).boxed();
    StreamableHttpPostResponse::Sse(events, None)
}

#[derive(Clone, Default)]
struct RecordingClient {
    post_limits: Arc<OnceLock<(usize, usize, usize)>>,
}

impl StreamableHttpClient for RecordingClient {
    type Error = reqwest::Error;

    async fn post_message(
        &self,
        _: Arc<str>,
        _: ClientJsonRpcMessage,
        _: Option<Arc<str>>,
        _: Option<String>,
        _: Headers,
    ) -> AdapterResult<StreamableHttpPostResponse> {
        Ok(ping_response())
    }

    async fn delete_session(
        &self,
        _: Arc<str>,
        _: Arc<str>,
        _: Option<String>,
        _: Headers,
    ) -> AdapterResult<()> {
        Ok(())
    }

    async fn get_stream(
        &self,
        _: Arc<str>,
        _: Option<Arc<str>>,
        _: Option<String>,
        _: Option<String>,
        _: Headers,
    ) -> AdapterResult<Events> {
        Err(StreamableHttpError::UnexpectedEndOfStream)
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        _: Arc<str>,
        _: ClientJsonRpcMessage,
        _: Option<Arc<str>>,
        _: Option<String>,
        _: Headers,
        _: usize,
    ) -> AdapterResult<StreamableHttpPostResponse> {
        Ok(ping_response())
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        _: Arc<str>,
        _: Option<Arc<str>>,
        _: Option<String>,
        _: Option<String>,
        _: Headers,
        _: usize,
    ) -> AdapterResult<Events> {
        Err(StreamableHttpError::UnexpectedEndOfStream)
    }

    async fn post_message_with_response_limits(
        &self,
        _: Arc<str>,
        _: ClientJsonRpcMessage,
        _: Option<Arc<str>>,
        _: Option<String>,
        _: Headers,
        limits: StreamableHttpResponseLimits,
    ) -> AdapterResult<StreamableHttpPostResponse> {
        let _ = self.post_limits.set((
            limits.max_sse_event_size,
            limits.max_json_response_size,
            limits.max_error_response_size,
        ));
        Ok(ping_response())
    }
}

#[tokio::test]
async fn sdk_forwards_all_post_limits_and_decodes_reqwest_sse() -> AdapterResult<()> {
    let client = RecordingClient::default();
    let config = StreamableHttpClientTransportConfig::with_uri("https://example.invalid/mcp")
        .max_sse_event_size(1024)
        .max_json_response_size(2048)
        .max_error_response_size(128);
    let mut transport = StreamableHttpClientTransport::with_client(client.clone(), config);
    let ping = ClientJsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(1),
    );

    transport.send(ping).await?;
    assert_eq!(client.post_limits.get(), Some(&(1024, 2048, 128)));
    assert!(matches!(
        transport.receive().await,
        Some(ServerJsonRpcMessage::Response(reply)) if reply.id == RequestId::Number(1)
    ));
    transport.close().await
}
