use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    io::stdout()
        .lock()
        .write_all(&efferian_hub::openapi_bytes()?)?;
    Ok(())
}
