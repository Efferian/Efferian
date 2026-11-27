//! Hub key derivation, credential verifiers and row-bound secret encryption.

pub mod auth;

use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce, aead::inout::InOutBuf};
use efferian_protocol::{
    AccountId, AccountKind, EnrollmentId, ExecutionId, HubId, NodeId, PrincipalId, SecretString,
    TokenId,
};
use hmac::{Hmac, Mac, digest::FixedOutput};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::storage::{ExpectedHubIdentity, MAX_WORK_BYTES, NewHubIdentity};

pub const ACTIVE_KEY_ID: u16 = 1;
const MAGIC: &[u8; 4] = b"EFS1";
const KEY_ID_BYTES: [u8; 2] = ACTIVE_KEY_ID.to_be_bytes();
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + KEY_ID_BYTES.len() + NONCE_BYTES;
const OVERHEAD: usize = HEADER_BYTES + TAG_BYTES;
const CRYPTO_OFFLOAD_BYTES: usize = 16 * 1024;

type SecretBytes = Zeroizing<[u8; 32]>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("system randomness is unavailable")]
    Randomness,
    #[error("failed to initialize HMAC")]
    Hmac,
    #[error("Vault payload exceeds the byte limit")]
    PayloadTooLarge,
    #[error("invalid Vault envelope")]
    InvalidEnvelope,
    #[error("Vault encryption failed")]
    Seal,
    #[error("Vault authentication failed")]
    Open,
    #[error("Vault background task failed")]
    Background(#[source] tokio::task::JoinError),
}

/// Keys derived from a master key before a Hub identity is available.
pub struct VaultKeys {
    aead: SecretBytes,
    token: SecretBytes,
    enrollment: SecretBytes,
    node: SecretBytes,
    fingerprint: SecretBytes,
}

impl VaultKeys {
    pub fn derive(master_key: SecretBytes) -> Result<Self, VaultError> {
        // RFC 5869: an absent salt is HashLen zero octets. All outputs here
        // are HashLen bytes, so each expansion uses exactly T(1).
        let mut extract = new_mac(&[0; 32])?;
        extract.update(master_key.as_slice());
        drop(master_key);
        let prk = finish_mac(extract);
        let expand = |info: &[u8]| {
            let mut mac = new_mac(prk.as_slice())?;
            mac.update(info);
            mac.update(&[1]);
            Ok(finish_mac(mac))
        };
        Ok(Self {
            aead: expand(b"efferian:v0:vault-aead")?,
            token: expand(b"efferian:v0:token-hmac")?,
            enrollment: expand(b"efferian:v0:enrollment-hmac")?,
            node: expand(b"efferian:v0:node-hmac")?,
            fingerprint: expand(b"efferian:v0:key-fingerprint")?,
        })
    }

    pub fn expected_hub_identity(&self) -> ExpectedHubIdentity {
        ExpectedHubIdentity {
            active_key_id: i64::from(ACTIVE_KEY_ID),
            master_key_fingerprint: encode_hex(self.fingerprint.as_slice()),
        }
    }

    pub fn new_hub_identity(&self, hub_id: HubId) -> NewHubIdentity {
        let identity = self.expected_hub_identity();
        NewHubIdentity {
            hub_id,
            active_key_id: identity.active_key_id,
            master_key_fingerprint: identity.master_key_fingerprint,
        }
    }

    pub fn bind_hub(self, hub_id: HubId) -> Vault {
        Vault { hub_id, keys: self }
    }

    pub fn issue_token(&self, id: TokenId) -> Result<IssuedCredential, VaultError> {
        self.issue(CredentialFamily::Token, id)
    }

    pub fn issue_enrollment(&self, id: EnrollmentId) -> Result<IssuedCredential, VaultError> {
        self.issue(CredentialFamily::Enrollment, id)
    }

    pub fn issue_node(&self, id: NodeId) -> Result<IssuedCredential, VaultError> {
        self.issue(CredentialFamily::Node, id)
    }

    fn issue(
        &self,
        family: CredentialFamily,
        id: impl fmt::Display,
    ) -> Result<IssuedCredential, VaultError> {
        let id = id.to_string();
        let mut secret_bytes = Zeroizing::new([0; 32]);
        fill_random(&mut *secret_bytes)?;
        let verifier = self.compute_verifier(family, &id, &secret_bytes)?;
        let mut secret = String::with_capacity("eff_".len() + id.len() + 1 + 64);
        secret.push_str("eff_");
        secret.push_str(&id);
        secret.push('.');
        push_hex(&mut secret, secret_bytes.as_slice());
        Ok(IssuedCredential {
            key_id: ACTIVE_KEY_ID,
            verifier: encode_hex(verifier.as_slice()),
            secret: SecretString::new(secret),
        })
    }

    fn compute_verifier(
        &self,
        family: CredentialFamily,
        id: &str,
        secret: &[u8; 32],
    ) -> Result<SecretBytes, VaultError> {
        let (key, domain) = match family {
            CredentialFamily::Token => (&self.token, b"efferian:v0:auth_tokens".as_slice()),
            CredentialFamily::Enrollment => {
                (&self.enrollment, b"efferian:v0:node_enrollments".as_slice())
            }
            CredentialFamily::Node => (&self.node, b"efferian:v0:nodes".as_slice()),
        };
        let mut mac = new_mac(key.as_slice())?;
        for part in [domain, id.as_bytes(), secret] {
            // Domain, branded ID and random secret are fixed and bounded.
            let length = u32::try_from(part.len()).map_err(|_| VaultError::Hmac)?;
            mac.update(&length.to_be_bytes());
            mac.update(part);
        }
        Ok(finish_mac(mac))
    }
}

pub struct Vault {
    hub_id: HubId,
    keys: VaultKeys,
}

#[derive(Clone, Copy)]
pub struct AccountAad {
    pub account_id: AccountId,
    pub secret_version: NonZeroU64,
    pub kind: AccountKind,
}

#[derive(Clone, Copy)]
pub struct ExecutionAad {
    pub execution_id: ExecutionId,
    pub caller_principal_id: PrincipalId,
}

pub struct IssuedCredential {
    pub key_id: u16,
    pub verifier: String,
    pub secret: SecretString,
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum CredentialFamily {
    Token,
    Enrollment,
    Node,
}

impl Vault {
    pub fn hub_id(&self) -> HubId {
        self.hub_id
    }

    pub fn issue_token(&self, id: TokenId) -> Result<IssuedCredential, VaultError> {
        self.keys.issue_token(id)
    }

    pub fn issue_enrollment(&self, id: EnrollmentId) -> Result<IssuedCredential, VaultError> {
        self.keys.issue_enrollment(id)
    }

    pub fn issue_node(&self, id: NodeId) -> Result<IssuedCredential, VaultError> {
        self.keys.issue_node(id)
    }

    pub fn seal_account(&self, aad: &AccountAad, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.seal(&self.account_aad(aad), plaintext)
    }

    pub fn open_account(
        &self,
        aad: &AccountAad,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.open(&self.account_aad(aad), envelope)
    }

    pub fn seal_execution(
        &self,
        aad: &ExecutionAad,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        self.seal(&self.execution_aad(aad), plaintext)
    }

    pub fn open_execution(
        &self,
        aad: &ExecutionAad,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.open(&self.execution_aad(aad), envelope)
    }

    /// Run outside the SQLite actor. Ownership keeps the plaintext zeroizing
    /// even when a caller cancels while the blocking task is running.
    pub async fn seal_execution_async(
        self: &Arc<Self>,
        aad: ExecutionAad,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, VaultError> {
        if plaintext.len() < CRYPTO_OFFLOAD_BYTES {
            return self.seal_execution(&aad, &plaintext);
        }
        let vault = Arc::clone(self);
        tokio::task::spawn_blocking(move || vault.seal_execution(&aad, &plaintext))
            .await
            .map_err(VaultError::Background)?
    }

    /// Run outside the SQLite actor.
    pub async fn open_execution_async(
        self: &Arc<Self>,
        aad: ExecutionAad,
        envelope: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if envelope.len() < CRYPTO_OFFLOAD_BYTES {
            return self.open_execution(&aad, &envelope);
        }
        let vault = Arc::clone(self);
        tokio::task::spawn_blocking(move || vault.open_execution(&aad, &envelope))
            .await
            .map_err(VaultError::Background)?
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.keys.aead).into())
    }

    fn seal(&self, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let size = plaintext
            .len()
            .checked_add(OVERHEAD)
            .filter(|size| *size <= MAX_WORK_BYTES)
            .ok_or(VaultError::PayloadTooLarge)?;
        let mut nonce = [0; NONCE_BYTES];
        fill_random(&mut nonce)?;
        let mut envelope = vec![0; size];
        envelope[..MAGIC.len()].copy_from_slice(MAGIC);
        envelope[MAGIC.len()..MAGIC.len() + KEY_ID_BYTES.len()].copy_from_slice(&KEY_ID_BYTES);
        envelope[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES].copy_from_slice(&nonce);
        let (output, tag_output) = envelope[HEADER_BYTES..].split_at_mut(plaintext.len());
        let buffer = InOutBuf::new(plaintext, output).map_err(|_| VaultError::Seal)?;
        let tag = self
            .cipher()
            .encrypt_inout_detached((&nonce).into(), aad.as_bytes(), buffer)
            .map_err(|_| VaultError::Seal)?;
        tag_output.copy_from_slice(&tag);
        Ok(envelope)
    }

    fn open(&self, aad: &str, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if envelope.len() > MAX_WORK_BYTES {
            return Err(VaultError::PayloadTooLarge);
        }
        if envelope.len() < OVERHEAD
            || !envelope.starts_with(MAGIC)
            || envelope[MAGIC.len()..MAGIC.len() + KEY_ID_BYTES.len()] != KEY_ID_BYTES
        {
            return Err(VaultError::InvalidEnvelope);
        }
        let nonce = <&XNonce>::try_from(&envelope[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES])
            .map_err(|_| VaultError::InvalidEnvelope)?;
        let (ciphertext, tag_bytes) = envelope[HEADER_BYTES..].split_at(envelope.len() - OVERHEAD);
        let tag = <&Tag>::try_from(tag_bytes).map_err(|_| VaultError::InvalidEnvelope)?;
        let mut plaintext = Zeroizing::new(vec![0; ciphertext.len()]);
        let buffer =
            InOutBuf::new(ciphertext, plaintext.as_mut_slice()).map_err(|_| VaultError::Open)?;
        self.cipher()
            .decrypt_inout_detached(nonce, aad.as_bytes(), buffer, tag)
            .map_err(|_| VaultError::Open)?;
        Ok(plaintext)
    }

    fn account_aad(&self, aad: &AccountAad) -> String {
        let kind = match aad.kind {
            AccountKind::HttpAuth => "http_auth",
            AccountKind::SshKey => "ssh_key",
            AccountKind::SecretKv => "secret_kv",
        };
        format!(
            "efferian:v0:{}:k{ACTIVE_KEY_ID}:account:{}:v{}:{kind}",
            self.hub_id, aad.account_id, aad.secret_version,
        )
    }

    fn execution_aad(&self, aad: &ExecutionAad) -> String {
        format!(
            "efferian:v0:{}:k{ACTIVE_KEY_ID}:execution:{}:{}",
            self.hub_id, aad.execution_id, aad.caller_principal_id,
        )
    }
}

fn new_mac(key: &[u8]) -> Result<HmacSha256, VaultError> {
    <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|_| VaultError::Hmac)
}

fn finish_mac(mac: HmacSha256) -> SecretBytes {
    let mut bytes = Zeroizing::new([0; 32]);
    mac.finalize_into((&mut *bytes).into());
    bytes
}

fn fill_random(bytes: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(bytes).map_err(|_| VaultError::Randomness)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    push_hex(&mut output, bytes);
    output
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests;
