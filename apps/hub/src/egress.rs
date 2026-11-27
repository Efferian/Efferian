//! HTTP transport for Hub upstreams with URL and connection-time address checks.

use std::sync::Arc;
use std::time::Duration;

use efferian_protocol::{
    EgressPolicy, EgressUrlMode, SsrfError, is_allowed_egress_ip, validate_egress_url,
};
use http::{HeaderMap, Method, header::HOST};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Body, Client, ClientBuilder, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct EgressClient {
    client: Client,
    policy: Arc<EgressPolicy>,
}

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("the TLS provider must be installed before starting Hub egress")]
    MissingTlsProvider,
    #[error("cannot initialize Hub egress: {0}")]
    Build(#[source] reqwest::Error),
    #[error(transparent)]
    Url(#[from] SsrfError),
    #[error("the Host header is derived from the upstream URL")]
    HostOverride,
    #[error("upstream HTTP request failed")]
    Http(#[source] reqwest::Error),
}

impl EgressClient {
    pub fn new(policy: EgressPolicy) -> Result<Self, EgressError> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(EgressError::MissingTlsProvider);
        }
        let policy = Arc::new(policy);
        let client = client_builder(Arc::clone(&policy), Arc::new(SystemResolver))
            .build()
            .map_err(EgressError::Build)?;
        Ok(Self { client, policy })
    }

    /// Send to an upstream selected by URL. The URL supplies the HTTP authority
    /// and the TLS identity for the same connection.
    pub async fn send(
        &self,
        method: Method,
        raw_url: &str,
        headers: HeaderMap,
        body: Option<Body>,
    ) -> Result<Response, EgressError> {
        let url = validate_egress_url(raw_url, &self.policy, EgressUrlMode::RequireHttpsByDefault)?;
        if headers.contains_key(HOST) {
            return Err(EgressError::HostOverride);
        }
        let mut request = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|error| EgressError::Http(error.without_url()))
    }
}

fn client_builder(policy: Arc<EgressPolicy>, resolver: Arc<dyn Resolve>) -> ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(CONNECT_TIMEOUT)
        .dns_resolver(Arc::new(ValidatingDnsResolver { policy, resolver }))
}

struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name.as_str().to_owned(), 0)).await?;
            Ok(Box::new(addrs) as Addrs)
        })
    }
}

struct ValidatingDnsResolver {
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolve>,
}

#[derive(Debug, thiserror::Error)]
enum ResolutionRejected {
    #[error("upstream DNS returned no addresses")]
    Empty,
    #[error("upstream DNS returned an address denied by the egress policy")]
    Denied,
}

impl Resolve for ValidatingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = self.resolver.resolve(name);
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            let addrs = lookup.await?.collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(ResolutionRejected::Empty.into());
            }
            if addrs
                .iter()
                .any(|addr| !is_allowed_egress_ip(addr.ip(), &policy))
            {
                return Err(ResolutionRejected::Denied.into());
            }
            // The connector uses these checked socket addresses, with the original
            // hostname still in the URL for the HTTP authority and TLS identity.
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests;
