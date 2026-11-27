pub(crate) mod accounts;
pub(crate) mod profiles;
pub(crate) mod references;
pub(crate) mod schema;
pub(crate) mod tools;
pub(crate) mod upstreams;

use http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use crate::http::RouteGroups;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Created,
    Updated,
    Unchanged,
}

impl Outcome {
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Created => StatusCode::CREATED,
            Self::Updated | Self::Unchanged => StatusCode::OK,
        }
    }
}

pub(crate) fn routes() -> RouteGroups {
    upstreams::routes()
        .merge(accounts::routes())
        .merge(tools::routes())
        .merge(profiles::routes())
}
