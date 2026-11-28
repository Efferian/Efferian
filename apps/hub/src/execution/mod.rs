pub(crate) mod invoke;
pub(crate) mod results;
pub(crate) mod state;

use crate::http::RouteGroups;

pub(crate) fn routes() -> RouteGroups {
    invoke::routes().merge(state::routes())
}
