//! Wire contracts and pure validation shared by Efferian applications.
//!
//! Use [`ToolDefinition::validate`] for authored catalog input and
//! [`ToolDefinition::freeze_revision`] to snapshot the schema and its digest.
//! [`ToolDefinition::resolve_managed`] produces an [`ExecuteReqPayload`] from
//! arguments and an authorized account. Node calls
//! [`ExecuteReqPayload::validate_resolved`] after [`decode_bridge_frame`], using
//! its own runtime and egress limits.
//!
//! [`validate_egress_url`] checks the URL before transport. The transport applies
//! [`is_allowed_egress_ip`] to resolved addresses and makes the connection to an
//! admitted address. File paths undergo local filesystem checks before use.
//!
//! Keep bridge buffers in the ownership returned by [`encode_bridge_frame`].
//! [`EventStreamFrame`] serializes to one JSON value per NDJSON line.
//! Enable `openapi` to export schemas for public API contracts.

pub mod digest;
pub mod domain;
pub mod id;
pub mod problem;

pub use digest::*;
pub use domain::*;
pub use id::*;
pub use problem::{PROBLEM_JSON_MEDIA_TYPE, ProblemDetails, error_codes};

pub mod action;
pub mod binding;
pub mod bridge;
pub mod event;
pub mod profile;
pub mod result;
pub mod secret;
pub mod ssh_key;
pub mod ssrf;
pub mod tool;
pub mod validate;
mod validation_error;
mod wire;

pub use action::*;
pub use binding::*;
pub use bridge::*;
pub use event::*;
pub use profile::*;
pub use result::*;
pub use secret::*;
pub use ssh_key::*;
pub use ssrf::*;
pub use tool::*;
pub use validate::*;
pub use validation_error::ValidationError;
