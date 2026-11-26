fn main() -> Result<(), &'static str> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "a TLS provider was already installed at startup")
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_installs_the_tls_provider() -> Result<(), &'static str> {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        super::main()?;
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        Ok(())
    }
}
