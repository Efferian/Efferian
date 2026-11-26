use efferian_protocol::{AccountNotBoundReason, error_codes as code};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    #[error("the caller token is invalid or inactive")]
    Unauthenticated,
    #[error("the caller is disabled")]
    PrincipalDisabled,
    #[error("the caller's owner is disabled")]
    OwnerDisabled,
    #[error("the caller's manager is disabled")]
    ManagedByDisabled,
    #[error("the authorization snapshot is incomplete or inconsistent")]
    InvalidAuthContext,
    #[error("resource not found")]
    ResourceNotFound,
    #[error("this operation requires a human administrator")]
    AdminHumanRequired,
    #[error("this operation requires an unrestricted token")]
    UnrestrictedTokenRequired,
    #[error("the requested token exceeds its authority for {0}")]
    TokenAmplification(&'static str),
    #[error("invalid or excessive time to live")]
    InvalidTtl,
    #[error("invalid grant scope")]
    InvalidGrantScope,
    #[error("node tag {tag} is outside the enrollment allowlist")]
    NodeTagNotAllowed { tag: String },
    #[error("the requested grant exceeds the delegator's effective capability")]
    GrantEscalation,
    #[error("the selected target is outside the caller's scope")]
    ScopeNarrowedOut,
    #[error("the caller lacks the required capability")]
    InsufficientCapability,
    #[error("the token withholds sensitive data")]
    SensitiveWithheld,
    #[error("operation forbidden")]
    Forbidden,
    #[error("no usable caller-bound account: {reason:?}")]
    AccountNotBound { reason: AccountNotBoundReason },
}

impl AuthzError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => code::UNAUTHENTICATED,
            Self::PrincipalDisabled => code::PRINCIPAL_DISABLED,
            Self::OwnerDisabled => code::OWNER_DISABLED,
            Self::ManagedByDisabled => code::MANAGED_BY_DISABLED,
            Self::ResourceNotFound => code::NOT_FOUND,
            Self::AdminHumanRequired => code::ADMIN_HUMAN_REQUIRED,
            Self::UnrestrictedTokenRequired => code::TOKEN_NARROWED,
            Self::TokenAmplification(_) => code::TOKEN_AMPLIFICATION,
            Self::InvalidTtl | Self::InvalidGrantScope => code::INVALID_INPUT,
            Self::NodeTagNotAllowed { .. } => code::NODE_TAG_NOT_ALLOWED,
            Self::AccountNotBound { .. } => code::ACCOUNT_NOT_BOUND,
            Self::InvalidAuthContext
            | Self::GrantEscalation
            | Self::ScopeNarrowedOut
            | Self::InsufficientCapability
            | Self::SensitiveWithheld
            | Self::Forbidden => code::FORBIDDEN,
        }
    }

    pub const fn status_code(&self) -> u16 {
        match self {
            Self::Unauthenticated => 401,
            Self::ResourceNotFound => 404,
            Self::InvalidTtl | Self::InvalidGrantScope => 400,
            _ => 403,
        }
    }
}
