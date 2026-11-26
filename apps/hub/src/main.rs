fn main() -> Result<(), &'static str> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "a TLS provider was already installed at startup")
}
