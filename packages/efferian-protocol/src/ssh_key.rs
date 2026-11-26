//! Bounded, structural validation of private key containers for SSH accounts.

use zeroize::Zeroizing;

use crate::{
    ValidationError,
    result::{decode_base64, decoded_base64_len},
};

pub const MAX_SSH_PRIVATE_KEY_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SshKeyError {
    #[error("invalid SSH private key PEM envelope")]
    InvalidPem,
    #[error("unsupported SSH private key container")]
    UnsupportedContainer,
    #[error("invalid DER private key structure")]
    InvalidDer,
    #[error("invalid or unsupported OpenSSH private key structure")]
    InvalidOpenSsh,
}

#[derive(Clone, Copy)]
enum Container {
    Pkcs8,
    Rsa,
    Ec,
    OpenSsh,
}

pub fn validate_ssh_private_key_pem(pem: &str) -> Result<(), ValidationError> {
    if pem.len() > MAX_SSH_PRIVATE_KEY_BYTES {
        return Err(SshKeyError::InvalidPem.into());
    }
    let mut lines = pem.trim().lines();
    let label = lines
        .next()
        .and_then(|line| line.strip_prefix("-----BEGIN "))
        .and_then(|line| line.strip_suffix("-----"))
        .ok_or(SshKeyError::InvalidPem)?;
    let container = match label {
        "PRIVATE KEY" => Container::Pkcs8,
        "RSA PRIVATE KEY" => Container::Rsa,
        "EC PRIVATE KEY" => Container::Ec,
        "OPENSSH PRIVATE KEY" => Container::OpenSsh,
        _ => return Err(SshKeyError::UnsupportedContainer.into()),
    };
    let footer = lines
        .next_back()
        .and_then(|line| line.strip_prefix("-----END "))
        .and_then(|line| line.strip_suffix("-----"));
    if footer != Some(label) {
        return Err(SshKeyError::InvalidPem.into());
    }

    let mut encoded = Zeroizing::new(String::with_capacity(pem.len()));
    for line in lines {
        for byte in line.bytes().filter(|b| !b.is_ascii_whitespace()) {
            if !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'=') {
                return Err(SshKeyError::InvalidPem.into());
            }
            encoded.push(char::from(byte));
        }
    }
    let len = decoded_base64_len(&encoded).map_err(|_| SshKeyError::InvalidPem)?;
    if len == 0 {
        return Err(SshKeyError::InvalidPem.into());
    }
    let bytes = decode_base64(&encoded, len).map_err(|_| SshKeyError::InvalidPem)?;

    if matches!(container, Container::OpenSsh) {
        valid_openssh(&bytes).ok_or(SshKeyError::InvalidOpenSsh)?;
    } else {
        valid_der(&bytes, container).ok_or(SshKeyError::InvalidDer)?;
    }
    Ok(())
}

struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (value, remaining) = self.0.split_at_checked(len)?;
        self.0 = remaining;
        Some(value)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn next_tag(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }

    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.byte()?;
        // All tags in the supported containers use the low-tag-number form.
        if tag == 0 || tag & 0x1f == 0x1f {
            return None;
        }
        let first = self.byte()?;
        let length = if first < 128 {
            usize::from(first)
        } else {
            let size = usize::from(first & 0x7f);
            if size == 0 || size > size_of::<usize>() {
                return None;
            }
            let encoded = self.take(size)?;
            if encoded.first() == Some(&0) {
                return None;
            }
            let length = encoded
                .iter()
                .fold(0usize, |n, &byte| (n << 8) | usize::from(byte));
            if length < 128 {
                return None;
            }
            length
        };
        Some((tag, self.take(length)?))
    }

    fn field(&mut self, expected: u8) -> Option<&'a [u8]> {
        let (tag, field) = self.tlv()?;
        (tag == expected).then_some(field)
    }

    fn version(&mut self) -> Option<u8> {
        let [version] = self.field(0x02)? else {
            return None;
        };
        Some(*version)
    }

    fn nonempty(&mut self, tag: u8) -> Option<&'a [u8]> {
        nonempty(self.field(tag)?)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn ssh_string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.take(len)
    }
}

fn nonempty(bytes: &[u8]) -> Option<&[u8]> {
    (!bytes.is_empty()).then_some(bytes)
}

fn valid_der(bytes: &[u8], container: Container) -> Option<()> {
    let mut der = Bytes(bytes);
    let mut fields = Bytes(der.field(0x30)?);
    der.end()?;
    let version = fields.version()?;

    match (container, version) {
        (Container::Pkcs8, 0 | 1) => {
            let mut algorithm = Bytes(fields.field(0x30)?);
            valid_oid(algorithm.nonempty(0x06)?)?;
            if !algorithm.0.is_empty() {
                let (tag, value) = algorithm.tlv()?;
                if tag & 0x20 != 0 {
                    valid_der_fields(value)?;
                }
            }
            algorithm.end()?;
            fields.nonempty(0x04)?;
            if fields.next_tag() == Some(0xa0) {
                let mut attributes = Bytes(fields.field(0xa0)?);
                while !attributes.0.is_empty() {
                    valid_der_fields(attributes.nonempty(0x30)?)?;
                }
            }
            let has_public_key = fields.next_tag() == Some(0x81);
            if (version == 1) != has_public_key {
                return None;
            }
            if has_public_key {
                valid_bit_string(fields.field(0x81)?)?;
            }
        }
        (Container::Rsa, 0 | 1) => {
            for _ in 0..8 {
                positive_integer(fields.nonempty(0x02)?)?;
            }
            if version == 1 {
                let mut primes = Bytes(fields.nonempty(0x30)?);
                while !primes.0.is_empty() {
                    let mut prime = Bytes(primes.field(0x30)?);
                    for _ in 0..3 {
                        positive_integer(prime.nonempty(0x02)?)?;
                    }
                    prime.end()?;
                }
            }
        }
        (Container::Ec, 1) => {
            fields.nonempty(0x04)?;
            if fields.next_tag() == Some(0xa0) {
                let mut params = Bytes(fields.field(0xa0)?);
                match params.tlv()? {
                    (0x06, oid) => valid_oid(oid)?,
                    (0x30, sequence) => valid_der_fields(nonempty(sequence)?)?,
                    _ => return None,
                }
                params.end()?;
            }
            if fields.next_tag() == Some(0xa1) {
                let mut public = Bytes(fields.field(0xa1)?);
                valid_bit_string(public.field(0x03)?)?;
                public.end()?;
            }
        }
        _ => return None,
    }
    fields.end()
}

fn valid_der_fields(bytes: &[u8]) -> Option<()> {
    let mut pending = vec![Bytes(bytes)];
    while let Some(mut fields) = pending.pop() {
        while !fields.0.is_empty() {
            let (tag, value) = fields.tlv()?;
            if tag & 0x20 != 0 {
                pending.push(Bytes(value));
            }
        }
    }
    Some(())
}

fn valid_oid(oid: &[u8]) -> Option<()> {
    nonempty(oid)?;
    let mut start = true;
    for &byte in oid {
        if start && byte == 0x80 {
            return None;
        }
        start = byte < 0x80;
    }
    start.then_some(())
}

fn valid_bit_string(bits: &[u8]) -> Option<()> {
    let (&unused, bytes) = bits.split_first()?;
    let &last = bytes.last()?;
    (unused < 8 && last & ((1 << unused) - 1) == 0).then_some(())
}

fn positive_integer(bytes: &[u8]) -> Option<()> {
    match bytes {
        [0, second, ..] if second & 0x80 != 0 => Some(()),
        [first, ..] if (1..=127).contains(first) => Some(()),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum SshKey {
    Rsa,
    Dsa,
    Ecdsa(&'static [u8]),
    Ed25519,
}

fn openssh_key_kind(name: &[u8]) -> Option<SshKey> {
    Some(match name {
        b"ssh-rsa" => SshKey::Rsa,
        b"ssh-dss" => SshKey::Dsa,
        b"ecdsa-sha2-nistp256" => SshKey::Ecdsa(b"nistp256"),
        b"ecdsa-sha2-nistp384" => SshKey::Ecdsa(b"nistp384"),
        b"ecdsa-sha2-nistp521" => SshKey::Ecdsa(b"nistp521"),
        b"ssh-ed25519" => SshKey::Ed25519,
        _ => return None,
    })
}

fn valid_openssh(bytes: &[u8]) -> Option<()> {
    let mut wire = Bytes(bytes.strip_prefix(b"openssh-key-v1\0")?);
    if wire.ssh_string()? != b"none"
        || wire.ssh_string()? != b"none"
        || !wire.ssh_string()?.is_empty()
        || wire.u32()? != 1
    {
        return None;
    }
    let mut public = Bytes(wire.ssh_string()?);
    let key_type = public.ssh_string()?;
    let kind = openssh_key_kind(key_type)?;
    openssh_fields(&mut public, kind, false)?;
    public.end()?;

    let mut private = Bytes(wire.ssh_string()?);
    wire.end()?;
    if private.0.is_empty()
        || !private.0.len().is_multiple_of(8)
        || private.u32()? != private.u32()?
        || private.ssh_string()? != key_type
    {
        return None;
    }
    openssh_fields(&mut private, kind, true)?;
    private.ssh_string()?; // Comment.
    let padding = private.0;
    (padding.len() < 8 && padding.iter().copied().eq(1..=padding.len() as u8)).then_some(())
}

fn openssh_fields(fields: &mut Bytes<'_>, kind: SshKey, private: bool) -> Option<()> {
    let integers = match kind {
        SshKey::Rsa => {
            if private {
                6
            } else {
                2
            }
        }
        SshKey::Dsa => {
            if private {
                5
            } else {
                4
            }
        }
        SshKey::Ecdsa(curve) => {
            if fields.ssh_string()? != curve {
                return None;
            }
            nonempty(fields.ssh_string()?)?;
            usize::from(private)
        }
        SshKey::Ed25519 => {
            if fields.ssh_string()?.len() != 32 || private && fields.ssh_string()?.len() != 64 {
                return None;
            }
            0
        }
    };
    for _ in 0..integers {
        positive_integer(fields.ssh_string()?)?;
    }
    Some(())
}
