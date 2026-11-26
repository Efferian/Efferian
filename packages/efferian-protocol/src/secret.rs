use crate::wire::strict_enum;

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    AccountKind, ValidationError,
    validate::{validate_http_header_value, validate_secret_header_name, validate_secret_key},
};

/// A secret backed by a zeroizing string. Serde explicitly reads and writes its wire value.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for SecretString {}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for SecretString {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, Type};
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Password)))
            .write_only(Some(true))
            .into()
    }
}

#[cfg(feature = "openapi")]
impl utoipa::ToSchema for SecretString {}

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
    pub enum HttpAuthSecret {
        Bearer {
            token: SecretString,
        },
        Header {
            name: String,
            value: SecretString,
        },
        Basic {
            username: String,
            password: SecretString,
        },
    }
}

impl HttpAuthSecret {
    pub fn ct_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bearer { token: a }, Self::Bearer { token: b }) => a.ct_eq(b),
            (Self::Header { name: a, value: av }, Self::Header { name: b, value: bv }) => {
                av.ct_eq(bv) & (a == b)
            }
            (
                Self::Basic {
                    username: a,
                    password: av,
                },
                Self::Basic {
                    username: b,
                    password: bv,
                },
            ) => av.ct_eq(bv) & (a == b),
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Bearer { token } => {
                if token.is_empty() {
                    return Err(ValidationError::InvalidField("bearer token"));
                }
                validate_http_header_value(token.expose_secret())
            }
            Self::Header { name, value } => {
                validate_secret_header_name(name)?;
                validate_http_header_value(value.expose_secret())
            }
            Self::Basic { username, password } => {
                if username.contains(':') {
                    return Err(ValidationError::InvalidField("Basic username"));
                }
                validate_http_header_value(username)?;
                validate_http_header_value(password.expose_secret())
            }
        }
    }

    pub fn header_name(&self) -> &str {
        match self {
            Self::Bearer { .. } | Self::Basic { .. } => "authorization",
            Self::Header { name, .. } => name,
        }
    }

    /// Materialize the credential after accounting for the exact header bytes.
    pub(crate) fn resolve_header(
        &self,
        remaining: &mut usize,
    ) -> Result<(String, SecretString), ValidationError> {
        use crate::validate::spend_action_bytes;

        self.validate()?;
        let name = self.header_name();
        spend_action_bytes(remaining, name.len())?;
        let value = match self {
            Self::Bearer { token } => {
                spend_action_bytes(remaining, "Bearer ".len().saturating_add(token.len()))?;
                let mut value =
                    Zeroizing::new(String::with_capacity("Bearer ".len() + token.len()));
                value.push_str("Bearer ");
                value.push_str(token.expose_secret());
                SecretString(value)
            }
            Self::Header { value, .. } => {
                spend_action_bytes(remaining, value.len())?;
                value.clone()
            }
            Self::Basic { username, password } => {
                let raw_len = username
                    .len()
                    .saturating_add(1)
                    .saturating_add(password.len());
                let encoded_len =
                    base64::encoded_len(raw_len, true).ok_or(ValidationError::ActionLimit)?;
                spend_action_bytes(remaining, "Basic ".len().saturating_add(encoded_len))?;
                let mut raw = Zeroizing::new(String::with_capacity(raw_len));
                raw.push_str(username);
                raw.push(':');
                raw.push_str(password.expose_secret());
                let mut value = Zeroizing::new(String::with_capacity("Basic ".len() + encoded_len));
                value.push_str("Basic ");
                STANDARD.encode_string(raw.as_bytes(), &mut value);
                SecretString(value)
            }
        };
        Ok((name.to_owned(), value))
    }
}

pub const MAX_SECRET_KV_ENTRIES: usize = 128;

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
    pub enum AccountSecretPayload {
        HttpAuth {
            auth: HttpAuthSecret,
        },
        SshKey {
            private_key_pem: SecretString,
        },
        SecretKv {
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            entries: BTreeMap<String, SecretString>,
        },
    }
}

impl AccountSecretPayload {
    pub const fn kind(&self) -> AccountKind {
        match self {
            Self::HttpAuth { .. } => AccountKind::HttpAuth,
            Self::SshKey { .. } => AccountKind::SshKey,
            Self::SecretKv { .. } => AccountKind::SecretKv,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::HttpAuth { auth } => auth.validate(),
            Self::SshKey { private_key_pem } => {
                crate::ssh_key::validate_ssh_private_key_pem(private_key_pem.expose_secret())
            }
            Self::SecretKv { entries } => {
                if !(1..=MAX_SECRET_KV_ENTRIES).contains(&entries.len()) {
                    return Err(ValidationError::InvalidField("secret entries count"));
                }
                entries.keys().try_for_each(|key| validate_secret_key(key))
            }
        }
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::HttpAuth { auth: a }, Self::HttpAuth { auth: b }) => a.ct_eq(b),
            (Self::SshKey { private_key_pem: a }, Self::SshKey { private_key_pem: b }) => {
                a.ct_eq(b)
            }
            (Self::SecretKv { entries: a }, Self::SecretKv { entries: b }) => {
                if a.len() != b.len() {
                    return false;
                }
                a.iter().zip(b).fold(true, |equal, ((ak, av), (bk, bv))| {
                    equal & (ak == bk) & av.ct_eq(bv)
                })
            }
            _ => false,
        }
    }
}
