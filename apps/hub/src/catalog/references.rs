//! Delete-time checks for live catalog references in the writer snapshot.

use std::collections::HashSet;

use efferian_protocol::{AccountId, AccountVisibility, ProfileId, ToolId, UpstreamId};
use rusqlite::{Connection, params};

use crate::storage::{StorageError, id};

/// Work-queue weight for catalog deletes that scan live catalog references.
pub(super) const DELETE_REFERENCE_WORK_BYTES: usize = 256 * 1024;

pub(crate) fn account_in_use(
    conn: &Connection,
    account: AccountId,
    visibility: AccountVisibility,
) -> Result<bool, StorageError> {
    let id_text = account.to_string();
    let referenced: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM account_bindings WHERE account_id = ?1)
                 OR EXISTS(SELECT 1 FROM executions WHERE account_id = ?1
                           AND state IN ('accepted', 'running'))",
        )?
        .query_row([&id_text], |row| row.get(0))?;
    if referenced || visibility == AccountVisibility::Private {
        // Tool definitions can only reference shared accounts.
        return Ok(referenced);
    }
    let matching = revisions_matching(
        conn,
        "SELECT tool_id, version FROM tool_revisions
         WHERE json_extract(definition_json, '$.spec.account_id') = ?1
            OR json_extract(definition_json, '$.spec.shared_account_id') = ?1",
        &id_text,
    )?;
    revisions_are_live(conn, &matching)
}

pub(crate) fn upstream_in_use(
    conn: &Connection,
    upstream: UpstreamId,
) -> Result<bool, StorageError> {
    let id_text = upstream.to_string();
    let referenced: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE upstream_id = ?1)
                 OR EXISTS(SELECT 1 FROM account_bindings WHERE upstream_id = ?1)
                 OR EXISTS(SELECT 1 FROM executions WHERE upstream_id = ?1
                           AND executor_kind = 'upstream' AND state IN ('accepted', 'running'))",
        )?
        .query_row([&id_text], |row| row.get(0))?;
    if referenced {
        return Ok(true);
    }
    let matching = revisions_matching(
        conn,
        "SELECT tool_id, version FROM tool_revisions
         WHERE json_extract(definition_json, '$.spec.kind') = 'upstream_ref'
           AND json_extract(definition_json, '$.spec.upstream_id') = ?1",
        &id_text,
    )?;
    revisions_are_live(conn, &matching)
}

pub(super) fn tool_in_use(conn: &Connection, tool: ToolId) -> Result<bool, StorageError> {
    let id_text = tool.to_string();
    let referenced: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE tool_id = ?1
                           AND state IN ('accepted', 'running'))
                 OR EXISTS(
                     SELECT 1 FROM profiles p, json_each(p.draft_bindings_json) b
                     WHERE json_extract(b.value, '$.tool_id') = ?1
                 )
                 OR EXISTS(
                     SELECT 1 FROM profiles p
                     JOIN profile_editions e
                       ON e.profile_id = p.profile_id AND e.version = p.published_version
                     JOIN json_each(e.bindings_json) b
                     WHERE p.published_version != 0 AND e.disabled_at_ms IS NULL
                       AND json_extract(b.value, '$.tool_id') = ?1
                 )",
        )?
        .query_row([&id_text], |row| row.get(0))?;
    Ok(referenced)
}

pub(super) fn profile_in_use(conn: &Connection, profile: ProfileId) -> Result<bool, StorageError> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE profile_id = ?1
                           AND state IN ('accepted', 'running'))",
        )?
        .query_row([profile.to_string()], |row| row.get(0))?)
}

fn revisions_matching(
    conn: &Connection,
    sql: &str,
    target_id: &str,
) -> Result<HashSet<(ToolId, u64)>, StorageError> {
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query([target_id])?;
    let mut matching = HashSet::new();
    while let Some(row) = rows.next()? {
        matching.insert((id::<ToolId>(row, 0)?, row.get::<_, u64>(1)?));
    }
    Ok(matching)
}

fn revisions_are_live(
    conn: &Connection,
    matching: &HashSet<(ToolId, u64)>,
) -> Result<bool, StorageError> {
    if matching.is_empty() {
        return Ok(false);
    }
    let mut current = conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM tools WHERE tool_id = ?1 AND current_version = ?2)",
    )?;
    for &(tool_id, version) in matching {
        let is_current: bool =
            current.query_row(params![tool_id.to_string(), version], |row| row.get(0))?;
        if is_current {
            return Ok(true);
        }
    }
    let mut bound = conn.prepare_cached(
        "SELECT EXISTS(
             SELECT 1 FROM profiles p, json_each(p.draft_bindings_json) b
             WHERE json_extract(b.value, '$.tool_id') = ?1
               AND json_extract(b.value, '$.tool_version') = ?2
         ) OR EXISTS(
             SELECT 1 FROM profiles p
             JOIN profile_editions e
               ON e.profile_id = p.profile_id AND e.version = p.published_version
             JOIN json_each(e.bindings_json) b
             WHERE p.published_version != 0 AND e.disabled_at_ms IS NULL
               AND json_extract(b.value, '$.tool_id') = ?1
               AND json_extract(b.value, '$.tool_version') = ?2
         )",
    )?;
    for &(tool_id, version) in matching {
        let live: bool =
            bound.query_row(params![tool_id.to_string(), version], |row| row.get(0))?;
        if live {
            return Ok(true);
        }
    }
    Ok(false)
}
