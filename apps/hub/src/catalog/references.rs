//! Delete-time checks for live catalog references in the writer snapshot.

use std::collections::HashSet;

use efferian_protocol::{
    AccountId, ProfileId, ProfileToolBinding, ToolDefinition, ToolId, ToolSpec, UpstreamId,
    validate_profile_bindings,
};
use rusqlite::{Connection, params};

use crate::storage::{StorageError, id, json};

use super::tools::static_account;

pub(crate) fn account_in_use(conn: &Connection, account: AccountId) -> Result<bool, StorageError> {
    let referenced: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM account_bindings WHERE account_id = ?1)
                 OR EXISTS(SELECT 1 FROM executions WHERE account_id = ?1
                           AND state IN ('accepted', 'running'))",
        )?
        .query_row([account.to_string()], |row| row.get(0))?;
    Ok(referenced
        || live_definitions_match(conn, |definition| {
            static_account(definition).is_some_and(|target| target.account_id == account)
        })?)
}

pub(crate) fn upstream_in_use(
    conn: &Connection,
    upstream: UpstreamId,
) -> Result<bool, StorageError> {
    let referenced: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE upstream_id = ?1)
                 OR EXISTS(SELECT 1 FROM account_bindings WHERE upstream_id = ?1)
                 OR EXISTS(SELECT 1 FROM executions WHERE upstream_id = ?1
                           AND executor_kind = 'upstream' AND state IN ('accepted', 'running'))",
        )?
        .query_row([upstream.to_string()], |row| row.get(0))?;
    Ok(referenced
        || live_definitions_match(
            conn,
            |definition| matches!(definition.spec, ToolSpec::UpstreamRef { upstream_id, .. } if upstream_id == upstream),
        )?)
}

pub(super) fn tool_in_use(conn: &Connection, tool: ToolId) -> Result<bool, StorageError> {
    let active: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE tool_id = ?1
                           AND state IN ('accepted', 'running'))",
        )?
        .query_row([tool.to_string()], |row| row.get(0))?;
    Ok(active || live_bindings_match(conn, |binding| Ok(binding.tool_id == tool))?)
}

pub(super) fn profile_in_use(conn: &Connection, profile: ProfileId) -> Result<bool, StorageError> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE profile_id = ?1
                           AND state IN ('accepted', 'running'))",
        )?
        .query_row([profile.to_string()], |row| row.get(0))?)
}

fn live_definitions_match(
    conn: &Connection,
    matches: impl Fn(&ToolDefinition) -> bool,
) -> Result<bool, StorageError> {
    let mut checked = HashSet::new();
    {
        let mut current = conn.prepare_cached(
            "SELECT t.tool_id, t.current_version, r.definition_json FROM tools t
             LEFT JOIN tool_revisions r ON r.tool_id = t.tool_id AND r.version = t.current_version",
        )?;
        let mut rows = current.query([])?;
        while let Some(row) = rows.next()? {
            let tool: ToolId = id(row, 0)?;
            let version: u64 = row.get(1)?;
            let definition: ToolDefinition = json(row, 2)?;
            if matches(&definition) {
                return Ok(true);
            }
            checked.insert((tool, version));
        }
    }
    let mut revision = conn.prepare_cached(
        "SELECT definition_json FROM tool_revisions WHERE tool_id = ?1 AND version = ?2",
    )?;
    live_bindings_match(conn, |binding| {
        if !checked.insert((binding.tool_id, binding.tool_version)) {
            return Ok(false);
        }
        let definition = revision.query_row(
            params![binding.tool_id.to_string(), binding.tool_version],
            |row| json(row, 0),
        )?;
        Ok(matches(&definition))
    })
}

fn live_bindings_match(
    conn: &Connection,
    mut matches: impl FnMut(&ProfileToolBinding) -> Result<bool, StorageError>,
) -> Result<bool, StorageError> {
    let mut statement = conn.prepare_cached(
        "SELECT draft_bindings_json FROM profiles
         UNION ALL
         SELECT e.bindings_json FROM profiles p LEFT JOIN profile_editions e
           ON e.profile_id = p.profile_id AND e.version = p.published_version
         WHERE p.published_version != 0 AND e.disabled_at_ms IS NULL",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let bindings: Vec<ProfileToolBinding> = json(row, 0)?;
        validate_profile_bindings(&bindings)
            .map_err(|_| StorageError::InvalidDatabase("invalid profile bindings"))?;
        for binding in &bindings {
            if matches(binding)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
