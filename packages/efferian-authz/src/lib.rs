//! Allow-only authorization of trusted Efferian state projections.
//!
//! Call [`check_active`] with the authenticated caller snapshot before admitting
//! work. Resource methods repeat the activity checks on the operation's own
//! consistent snapshot. Supply trusted catalog, node, and ownership projections.
//!
//! Use [`authorize_discovery_target`] for each candidate and
//! [`authorize_profile_invoke`] for the selected target. For a caller-bound tool,
//! [`check_profile_invoke_metadata`] can guard the lookup of account bindings.
//! Open the account only after the final authorization returns its ID.
//!
//! Execution access and stream visibility use the recorded ownership and target
//! attributes together with the reading token's current scope. Use
//! [`can_read_sensitive_result`] before retrieving result data.

mod error;
mod model;
mod policy;

pub use error::AuthzError;
pub use model::*;
pub use policy::{authorize_admin, check_active};

mod account;
mod events;
mod execution;
mod invoke;

pub use account::*;
pub use events::*;
pub use execution::*;
pub use invoke::*;

mod node;
mod principal;
mod token;

pub use node::*;
pub use principal::*;
pub use token::*;
