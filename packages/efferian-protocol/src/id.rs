use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize, de};
use uuid::{Uuid, Variant, Version};

use crate::{AggregateType, PrincipalKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("invalid identifier prefix")]
    InvalidPrefix,
    #[error("invalid identifier length")]
    InvalidLength,
    #[error("invalid identifier encoding")]
    InvalidHex,
    #[error("identifier must be an RFC 9562 UUIDv7")]
    NotUuidV7,
}

fn validated_v7(uuid: Uuid) -> Result<Uuid, IdError> {
    if uuid.get_version() != Some(Version::SortRand) || uuid.get_variant() != Variant::RFC4122 {
        return Err(IdError::NotUuidV7);
    }
    Ok(uuid)
}

fn branded_uuid(hex: &str) -> Result<Uuid, IdError> {
    if hex.len() != 32 {
        return Err(IdError::InvalidLength);
    }
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(IdError::InvalidHex);
    }
    validated_v7(Uuid::parse_str(hex).map_err(|_| IdError::InvalidHex)?)
}

fn timestamp_ms(uuid: Uuid) -> i64 {
    // The most significant 48 bits of UUIDv7 contain Unix milliseconds.
    (uuid.as_u128() >> 80) as i64
}

macro_rules! text_id {
    ($name:ident) => {
        impl $name {
            pub fn parse(input: &str) -> Result<Self, IdError> {
                input.parse()
            }
        }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct IdVisitor;

                impl de::Visitor<'_> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(concat!("a valid ", stringify!($name), " string"))
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

#[cfg(feature = "openapi")]
fn pattern_schema(pattern: &str) -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{ObjectBuilder, Type};
    ObjectBuilder::new()
        .schema_type(Type::String)
        .pattern(Some(pattern))
        .into()
}

macro_rules! branded_schema {
    ($name:ident, $prefix:literal) => {
        #[cfg(feature = "openapi")]
        impl utoipa::PartialSchema for $name {
            fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                pattern_schema(concat!(
                    "^",
                    $prefix,
                    "_[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$"
                ))
            }
        }
        #[cfg(feature = "openapi")]
        impl utoipa::ToSchema for $name {}
    };
}

macro_rules! branded_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        // Generating a fresh identifier is an explicit operation.
        #[allow(clippy::new_without_default)]
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            pub fn from_uuid(uuid: Uuid) -> Result<Self, IdError> {
                validated_v7(uuid).map(Self)
            }
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
            pub const fn prefix() -> &'static str {
                concat!($prefix, "_")
            }
            pub fn timestamp_ms(self) -> i64 {
                timestamp_ms(self.0)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", Self::prefix(), self.0.simple())
            }
        }
        impl FromStr for $name {
            type Err = IdError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let hex = input
                    .strip_prefix(Self::prefix())
                    .ok_or(IdError::InvalidPrefix)?;
                branded_uuid(hex).map(Self)
            }
        }

        text_id!($name);
        branded_schema!($name, $prefix);
    };
}

branded_id!(HubId, "hub");
branded_id!(EnrollmentId, "enr");
branded_id!(NodeId, "node");
branded_id!(UpstreamId, "up");
branded_id!(AccountId, "acc");
branded_id!(ToolId, "tool");
branded_id!(ProfileId, "prof");
branded_id!(GrantId, "grnt");
branded_id!(ExecutionId, "exec");
branded_id!(EventId, "evt");
branded_id!(TraceId, "req");

macro_rules! prefix_id {
    ($name:ident, $prefix:ident, $pattern:literal, $($variant:ident => $text:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $prefix { $($variant),+ }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name {
            prefix: $prefix,
            uuid: Uuid,
        }

        impl $name {
            fn new(prefix: $prefix) -> Self {
                Self { prefix, uuid: Uuid::now_v7() }
            }
            pub fn from_parts(prefix: $prefix, uuid: Uuid) -> Result<Self, IdError> {
                Ok(Self { prefix, uuid: validated_v7(uuid)? })
            }
            pub const fn as_uuid(self) -> Uuid {
                self.uuid
            }
            pub const fn prefix(self) -> $prefix {
                self.prefix
            }
            pub fn timestamp_ms(self) -> i64 {
                timestamp_ms(self.uuid)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let prefix = match self.prefix { $($prefix::$variant => $text),+ };
                write!(f, "{prefix}_{}", self.uuid.simple())
            }
        }
        impl FromStr for $name {
            type Err = IdError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let (prefix, hex) = input.split_once('_').ok_or(IdError::InvalidPrefix)?;
                let prefix = match prefix {
                    $($text => $prefix::$variant,)+
                    _ => return Err(IdError::InvalidPrefix),
                };
                Ok(Self { prefix, uuid: branded_uuid(hex)? })
            }
        }

        text_id!($name);
        branded_schema!($name, $pattern);
    };
}

prefix_id!(PrincipalId, PrincipalPrefix, "(usr|agt|sp)", Usr => "usr", Agt => "agt", Sp => "sp");
prefix_id!(TokenId, TokenPrefix, "(tok|spk)", Tok => "tok", Spk => "spk");

impl PrincipalId {
    pub fn new_user() -> Self {
        Self::new(PrincipalPrefix::Usr)
    }

    pub fn new_agent() -> Self {
        Self::new(PrincipalPrefix::Agt)
    }

    pub fn new_service() -> Self {
        Self::new(PrincipalPrefix::Sp)
    }

    pub fn new_for_kind(kind: PrincipalKind) -> Self {
        Self::new(Self::prefix_for_kind(kind))
    }

    pub fn matches_kind(self, kind: PrincipalKind) -> bool {
        self.prefix == Self::prefix_for_kind(kind)
    }

    fn prefix_for_kind(kind: PrincipalKind) -> PrincipalPrefix {
        match kind {
            PrincipalKind::Admin | PrincipalKind::Member => PrincipalPrefix::Usr,
            PrincipalKind::Agent => PrincipalPrefix::Agt,
            PrincipalKind::Service => PrincipalPrefix::Sp,
        }
    }
}

impl TokenId {
    pub fn new_user_or_agent() -> Self {
        Self::new(TokenPrefix::Tok)
    }

    pub fn new_service() -> Self {
        Self::new(TokenPrefix::Spk)
    }

    pub fn new_for_kind(kind: PrincipalKind) -> Self {
        Self::new(Self::prefix_for_kind(kind))
    }

    pub fn matches_kind(self, kind: PrincipalKind) -> bool {
        self.prefix == Self::prefix_for_kind(kind)
    }

    fn prefix_for_kind(kind: PrincipalKind) -> TokenPrefix {
        match kind {
            PrincipalKind::Admin | PrincipalKind::Member | PrincipalKind::Agent => TokenPrefix::Tok,
            PrincipalKind::Service => TokenPrefix::Spk,
        }
    }
}

macro_rules! union_id {
    ($name:ident, $pattern:literal, $($variant:ident($id:ty) => $($prefix:literal)|+),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($variant($id)),+ }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self { $(Self::$variant(id) => fmt::Display::fmt(id, f)),+ }
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let (prefix, _) = input.split_once('_').ok_or(IdError::InvalidPrefix)?;
                match prefix {
                    $($($prefix)|+ => input.parse().map(Self::$variant),)+
                    _ => Err(IdError::InvalidPrefix),
                }
            }
        }

        text_id!($name);
        branded_schema!($name, $pattern);
    };
}

union_id!(
    ActorId, "(usr|agt|sp|node|hub)",
    Principal(PrincipalId) => "usr" | "agt" | "sp",
    Node(NodeId) => "node",
    Hub(HubId) => "hub",
);

union_id!(
    AggregateId, "(exec|node|prof|usr|agt|sp|tok|spk)",
    Execution(ExecutionId) => "exec",
    Node(NodeId) => "node",
    Profile(ProfileId) => "prof",
    Principal(PrincipalId) => "usr" | "agt" | "sp",
    Token(TokenId) => "tok" | "spk",
);

impl AggregateId {
    pub const fn aggregate_type(self) -> AggregateType {
        match self {
            Self::Execution(_) => AggregateType::Execution,
            Self::Node(_) => AggregateType::Node,
            Self::Profile(_) => AggregateType::Profile,
            Self::Principal(_) => AggregateType::Principal,
            Self::Token(_) => AggregateType::Token,
        }
    }
}

pub const DEFAULT_REQUEST_ID_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_REQUEST_ID_MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestIdFreshnessError {
    #[error("request ID timestamp {timestamp_ms} is older than {max_age_ms} ms at {now_ms}")]
    Expired {
        timestamp_ms: i64,
        now_ms: i64,
        max_age_ms: i64,
    },
    #[error(
        "request ID timestamp {timestamp_ms} is more than {max_future_skew_ms} ms ahead of {now_ms}"
    )]
    TooFarInFuture {
        timestamp_ms: i64,
        now_ms: i64,
        max_future_skew_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(Uuid);

#[allow(clippy::new_without_default)]
impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Result<Self, IdError> {
        validated_v7(uuid).map(Self)
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    pub fn timestamp_ms(self) -> i64 {
        timestamp_ms(self.0)
    }

    pub fn canonical_str(self) -> String {
        self.to_string()
    }

    pub fn validate_freshness(
        self,
        now_ms: i64,
        max_age_ms: i64,
        max_future_skew_ms: i64,
    ) -> Result<(), RequestIdFreshnessError> {
        let timestamp_ms = self.timestamp_ms();
        if timestamp_ms < now_ms.saturating_sub(max_age_ms) {
            return Err(RequestIdFreshnessError::Expired {
                timestamp_ms,
                now_ms,
                max_age_ms,
            });
        }
        if timestamp_ms > now_ms.saturating_add(max_future_skew_ms) {
            return Err(RequestIdFreshnessError::TooFarInFuture {
                timestamp_ms,
                now_ms,
                max_future_skew_ms,
            });
        }
        Ok(())
    }

    /// Schema for the canonical representation in responses.
    #[cfg(feature = "openapi")]
    pub fn canonical_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        pattern_schema("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

impl FromStr for RequestId {
    type Err = IdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !matches!(input.len(), 32 | 36) {
            return Err(IdError::InvalidLength);
        }
        let hyphenated = input.len() == 36;
        let valid = input.bytes().enumerate().all(|(index, byte)| {
            if hyphenated && matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
        if !valid {
            return Err(IdError::InvalidHex);
        }
        Self::from_uuid(Uuid::parse_str(input).map_err(|_| IdError::InvalidHex)?)
    }
}

text_id!(RequestId);

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for RequestId {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{OneOfBuilder, Type};

        OneOfBuilder::new()
            .schema_type(Type::String)
            .item(pattern_schema("^[0-9a-fA-F]{12}7[0-9a-fA-F]{3}[89aAbB][0-9a-fA-F]{15}$"))
            .item(pattern_schema(
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
            ))
            .into()
    }
}

#[cfg(feature = "openapi")]
impl utoipa::ToSchema for RequestId {}
