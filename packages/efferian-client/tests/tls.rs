use std::error::Error;

use rustls::crypto::{CryptoProvider, ring};
use rustls_pki_types::{CertificateDer, pem::PemObject};

// This integration-test executable starts with a fresh process-wide provider.
#[test]
fn ring_client_builds_a_query_and_reads_pem() -> Result<(), Box<dyn Error>> {
    assert!(CryptoProvider::get_default().is_none());
    ring::default_provider()
        .install_default()
        .map_err(|_| "a TLS provider was already installed")?;

    let client = reqwest::Client::builder().build()?;
    let request = client
        .get("https://example.invalid/")
        .query(&[("key", "a b")])
        .build()?;
    assert_eq!(request.url().query(), Some("key=a+b"));

    let pem = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let blocks = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(blocks, [CertificateDer::from_slice(&[1, 2, 3])]);
    Ok(())
}
