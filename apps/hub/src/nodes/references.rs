use efferian_protocol::{
    NodeId, ProfileToolBinding, TargetSelector, ToolDefinition, validate_profile_bindings,
};
use rusqlite::{Connection, params};

use crate::storage::{WriteTxError, json};

use super::NodeWriteResult;

pub(super) fn node_in_use(conn: &Connection, node_id: NodeId) -> NodeWriteResult<bool> {
    let active: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM executions WHERE node_id = ?1 AND state IN ('accepted', 'running')
        )",
        [node_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(active
        || current_tools_use_node(conn, node_id)?
        || profile_bindings_use_node(conn, node_id)?)
}

fn current_tools_use_node(conn: &Connection, node_id: NodeId) -> NodeWriteResult<bool> {
    // A missing revision is an invalid catalog entry. Select it as NULL so
    // decoding fails closed instead of silently treating the tool as unrelated.
    let mut statement = conn.prepare_cached(
        "SELECT r.definition_json FROM tools t LEFT JOIN tool_revisions r
           ON r.tool_id = t.tool_id AND r.version = t.current_version",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if targets_node(json(row, 0)?, node_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn profile_bindings_use_node(conn: &Connection, node_id: NodeId) -> NodeWriteResult<bool> {
    let mut statement = conn.prepare_cached(
        "SELECT draft_bindings_json FROM profiles
         UNION ALL
         SELECT e.bindings_json FROM profiles p LEFT JOIN profile_editions e
           ON e.profile_id = p.profile_id AND e.version = p.published_version
         WHERE p.published_version > 0 AND e.disabled_at_ms IS NULL",
    )?;
    let mut revisions = conn.prepare_cached(
        "SELECT definition_json FROM tool_revisions WHERE tool_id = ?1 AND version = ?2",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let bindings: Vec<ProfileToolBinding> = json(row, 0)?;
        validate_profile_bindings(&bindings)
            .map_err(|_| WriteTxError::InvalidDatabase("invalid profile bindings"))?;
        for binding in bindings {
            if binding.fixed_node_id == Some(node_id) {
                return Ok(true);
            }
            let definition = revisions.query_row(
                params![binding.tool_id.to_string(), binding.tool_version],
                |row| json(row, 0),
            )?;
            if targets_node(definition, node_id)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn targets_node(definition: ToolDefinition, node_id: NodeId) -> NodeWriteResult<bool> {
    let Some(selector) = definition.spec.target_selector() else {
        return Ok(false);
    };
    selector
        .validate()
        .map_err(|_| WriteTxError::InvalidDatabase("invalid tool target selector"))?;
    Ok(matches!(selector, TargetSelector::Fixed { node_ids } if node_ids.contains(&node_id)))
}
