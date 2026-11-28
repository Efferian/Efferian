pub(crate) mod accounts;
pub(crate) mod profiles;
pub(crate) mod references;
pub(crate) mod schema;
pub(crate) mod tools;
pub(crate) mod upstreams;

pub(crate) use crate::http::Outcome;
use crate::http::RouteGroups;

pub(crate) fn routes() -> RouteGroups {
    upstreams::routes()
        .merge(accounts::routes())
        .merge(tools::routes())
        .merge(profiles::routes())
}
