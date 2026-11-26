use crate::{SshKeyError, SsrfError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("ValueBinding::Secret is forbidden in argv and HTTP fields")]
    SecretForbiddenInArgv,
    #[error("ValueBinding::Arg is forbidden in env")]
    ArgForbiddenInEnv,
    #[error("a bound argument is missing")]
    MissingArgument,
    #[error("a text binding requires a string, number, or boolean")]
    InvalidTextArgument,
    #[error("a bound secret is missing")]
    MissingSecret,
    #[error("invalid {0}")]
    InvalidField(&'static str),
    #[error("incompatible account or credential fields")]
    InvalidAccount,
    #[error("a header name is repeated or collides with the authentication header")]
    HeaderCollision,
    #[error(transparent)]
    InvalidSshKey(#[from] SshKeyError),
    #[error("invalid runtime limit")]
    RuntimeLimit,
    #[error("output exceeds the byte limit")]
    OutputLimit,
    #[error("invalid base64 output")]
    InvalidOutputEncoding,
    #[error("invalid execution receipt")]
    InvalidReceipt,
    #[error("tool definition exceeds the byte limit")]
    DefinitionLimit,
    #[error("resolved action exceeds the byte limit")]
    ActionLimit,
    #[error("invalid JSON encoding")]
    InvalidJson,
    #[error("the upstream discovery snapshot does not match the referenced tool")]
    MissingUpstreamTool,
    #[error(transparent)]
    Egress(#[from] SsrfError),
}
