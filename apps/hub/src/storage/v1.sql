CREATE TABLE hub_meta (
    id                        INTEGER PRIMARY KEY CHECK (id = 1),
    hub_id                    TEXT    NOT NULL,
    active_key_id             INTEGER NOT NULL DEFAULT 1,
    master_key_fingerprint    TEXT    NOT NULL,
    gc_purging_principal_id   TEXT REFERENCES principals(principal_id) ON DELETE SET NULL,
    events_pruned_through_seq INTEGER NOT NULL DEFAULT 0,
    events_head_seq           INTEGER NOT NULL DEFAULT 0,
    created_at_ms             INTEGER NOT NULL,
    updated_at_ms             INTEGER NOT NULL
);


CREATE TABLE principals (
    principal_id            TEXT    PRIMARY KEY,
    kind                    TEXT    NOT NULL CHECK (kind IN ('admin', 'member', 'agent', 'service')),
    name                    TEXT    NOT NULL UNIQUE,
    owner_principal_id      TEXT    REFERENCES principals(principal_id) ON DELETE RESTRICT,
    managed_by_principal_id TEXT    REFERENCES principals(principal_id) ON DELETE RESTRICT,
    inherit_owner_bindings  INTEGER NOT NULL DEFAULT 0 CHECK (inherit_owner_bindings IN (0, 1)),
    is_orchestrator         INTEGER NOT NULL DEFAULT 0 CHECK (is_orchestrator IN (0, 1)),
    allowed_node_tags_json  TEXT    NOT NULL DEFAULT '[]',
    observe_executions      INTEGER NOT NULL DEFAULT 0 CHECK (observe_executions IN (0, 1)),
    disabled_at_ms          INTEGER,
    created_at_ms           INTEGER NOT NULL,
    updated_at_ms           INTEGER NOT NULL,
    CHECK (owner_principal_id IS NULL OR kind = 'agent'),
    CHECK (managed_by_principal_id IS NULL OR kind = 'agent'),
    CHECK (inherit_owner_bindings = 0 OR (kind = 'agent' AND owner_principal_id IS NOT NULL)),
    CHECK (is_orchestrator = 0 OR kind = 'service'),
    CHECK (allowed_node_tags_json = '[]' OR is_orchestrator = 1),
    CHECK (observe_executions = 0 OR kind = 'service')
);


CREATE TABLE auth_tokens (
    token_id              TEXT    PRIMARY KEY,
    principal_id          TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    created_by            TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    label                 TEXT    NOT NULL,
    key_id                INTEGER NOT NULL DEFAULT 1,
    verifier_hmac         TEXT    NOT NULL UNIQUE,
    max_capability        TEXT    CHECK (max_capability IN ('discover', 'invoke', 'admin')),
    allowed_profiles_json TEXT,
    allowed_nodes_json    TEXT,
    withhold_sensitive    INTEGER NOT NULL DEFAULT 0 CHECK (withhold_sensitive IN (0, 1)),
    expires_at_ms         INTEGER,
    revoked_at_ms         INTEGER,
    created_at_ms         INTEGER NOT NULL
);
CREATE INDEX idx_auth_tokens_principal ON auth_tokens(principal_id);
CREATE INDEX idx_auth_tokens_expires ON auth_tokens(expires_at_ms) WHERE expires_at_ms IS NOT NULL;
CREATE INDEX idx_auth_tokens_revoked ON auth_tokens(revoked_at_ms) WHERE revoked_at_ms IS NOT NULL;


CREATE TABLE node_enrollments (
    enrollment_id           TEXT    PRIMARY KEY,
    key_id                  INTEGER NOT NULL DEFAULT 1,
    verifier_hmac           TEXT    NOT NULL UNIQUE,
    target_node_name        TEXT,
    target_node_id          TEXT    REFERENCES nodes(node_id) ON DELETE CASCADE,
    tags_json               TEXT    NOT NULL DEFAULT '[]',
    managed_by_principal_id TEXT    REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_by              TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    expires_at_ms           INTEGER NOT NULL,
    consumed_at_ms          INTEGER,
    revoked_at_ms           INTEGER,
    created_at_ms           INTEGER NOT NULL,
    CHECK ((target_node_name IS NOT NULL AND target_node_id IS NULL)
        OR (target_node_name IS NULL AND target_node_id IS NOT NULL))
);
CREATE INDEX idx_node_enrollments_expires ON node_enrollments(expires_at_ms);


CREATE TABLE nodes (
    node_id                   TEXT    PRIMARY KEY,
    name                      TEXT    NOT NULL,
    key_id                    INTEGER NOT NULL DEFAULT 1,
    credential_hmac           TEXT    NOT NULL UNIQUE,
    session_epoch             INTEGER NOT NULL DEFAULT 0,
    tags_json                 TEXT    NOT NULL DEFAULT '[]',
    managed_by_principal_id   TEXT    REFERENCES principals(principal_id) ON DELETE RESTRICT,
    platform_os               TEXT    CHECK (platform_os IS NULL OR platform_os IN ('linux', 'macos')),
    platform_arch             TEXT,
    allowed_cwd_roots_json    TEXT    NOT NULL DEFAULT '[]',
    max_concurrent_executions INTEGER,
    last_connected_at_ms      INTEGER,
    last_disconnected_at_ms   INTEGER,
    revoked_at_ms             INTEGER,
    created_at_ms             INTEGER NOT NULL,
    updated_at_ms             INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_nodes_active_name ON nodes(name) WHERE revoked_at_ms IS NULL;


CREATE TABLE upstreams (
    upstream_id           TEXT    PRIMARY KEY,
    slug                  TEXT    NOT NULL UNIQUE,
    url                   TEXT    NOT NULL,
    headers_template_json TEXT    NOT NULL DEFAULT '{}',
    config_version        INTEGER NOT NULL DEFAULT 1,
    discovered_tools_json TEXT    NOT NULL DEFAULT '[]',
    discovered_at_ms      INTEGER,
    disabled_at_ms        INTEGER,
    created_at_ms         INTEGER NOT NULL,
    updated_at_ms         INTEGER NOT NULL
);


CREATE TABLE accounts (
    account_id         TEXT    PRIMARY KEY,
    slug               TEXT    NOT NULL,
    owner_principal_id TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    visibility         TEXT    NOT NULL CHECK (visibility IN ('private', 'shared')),
    kind               TEXT    NOT NULL CHECK (kind IN ('http_auth', 'ssh_key', 'secret_kv')),
    upstream_id        TEXT    REFERENCES upstreams(upstream_id) ON DELETE RESTRICT,
    sealed_secret_blob BLOB    NOT NULL,
    secret_version     INTEGER NOT NULL DEFAULT 1,
    created_at_ms      INTEGER NOT NULL,
    updated_at_ms      INTEGER NOT NULL,
    CHECK (upstream_id IS NULL OR kind = 'http_auth')
);
CREATE UNIQUE INDEX idx_accounts_shared_slug ON accounts(slug) WHERE visibility = 'shared';
CREATE UNIQUE INDEX idx_accounts_private_owner_slug ON accounts(owner_principal_id, slug) WHERE visibility = 'private';


CREATE TABLE account_bindings (
    principal_id  TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    upstream_id   TEXT    NOT NULL REFERENCES upstreams(upstream_id) ON DELETE CASCADE,
    account_id    TEXT    NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal_id, upstream_id)
);


CREATE TABLE tools (
    tool_id         TEXT    PRIMARY KEY,
    slug            TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL CHECK (kind IN ('command', 'script', 'http', 'ssh', 'upstream_ref')),
    created_by      TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    current_version INTEGER NOT NULL DEFAULT 1,
    disabled_at_ms  INTEGER,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL
);


CREATE TABLE tool_revisions (
    tool_id             TEXT    NOT NULL REFERENCES tools(tool_id) ON DELETE RESTRICT,
    version             INTEGER NOT NULL,
    definition_json     TEXT    NOT NULL,
    input_schema_sha256 TEXT    NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (tool_id, version)
);


CREATE TABLE profiles (
    profile_id          TEXT    PRIMARY KEY,
    slug                TEXT    NOT NULL UNIQUE,
    discovery_mode      TEXT    NOT NULL CHECK (discovery_mode IN ('full', 'curated', 'search')),
    published_version   INTEGER NOT NULL DEFAULT 0,
    draft_bindings_json TEXT    NOT NULL DEFAULT '[]',
    disabled_at_ms      INTEGER,
    created_at_ms       INTEGER NOT NULL,
    updated_at_ms       INTEGER NOT NULL
);


CREATE TABLE profile_editions (
    profile_id      TEXT    NOT NULL REFERENCES profiles(profile_id) ON DELETE RESTRICT,
    version         INTEGER NOT NULL,
    discovery_mode  TEXT    NOT NULL CHECK (discovery_mode IN ('full', 'curated', 'search')),
    bindings_json   TEXT    NOT NULL,
    published_by    TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    published_at_ms INTEGER NOT NULL,
    disabled_at_ms  INTEGER,
    PRIMARY KEY (profile_id, version)
);


CREATE TABLE grants (
    grant_id      TEXT    PRIMARY KEY,
    principal_id  TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    scope_kind    TEXT    NOT NULL CHECK (scope_kind IN ('global', 'profile')),
    scope_id      TEXT    NOT NULL DEFAULT '',
    capability    TEXT    NOT NULL CHECK (capability IN ('discover', 'invoke', 'admin')),
    created_by    TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (principal_id, scope_kind, scope_id, capability),
    CHECK ((scope_kind = 'global' AND scope_id = '') OR (scope_kind = 'profile' AND scope_id != '')),
    CHECK (capability != 'admin' OR scope_kind = 'global')
);
CREATE INDEX idx_grants_principal ON grants(principal_id);


CREATE TABLE executions (
    execution_id           TEXT    PRIMARY KEY,
    invoke_kind            TEXT    NOT NULL CHECK (invoke_kind IN ('profile', 'tool_test')),
    request_id             TEXT    NOT NULL,
    request_digest         TEXT    NOT NULL,
    caller_principal_id    TEXT    NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    caller_token_id        TEXT    NOT NULL,
    profile_id             TEXT,
    profile_version        INTEGER,
    tool_id                TEXT    NOT NULL,
    tool_version           INTEGER NOT NULL,
    public_name            TEXT    NOT NULL,
    executor_kind          TEXT    NOT NULL CHECK (executor_kind IN ('node', 'upstream')),
    node_id                TEXT,
    node_session_epoch     INTEGER,
    upstream_id            TEXT,
    account_id             TEXT,
    state                  TEXT    NOT NULL CHECK (state IN (
                               'accepted', 'running', 'succeeded', 'failed',
                               'cancelled', 'timed_out', 'unknown'
                           )),
    cancel_requested_at_ms INTEGER,
    late_receipt_at_ms     INTEGER,
    summary_json           TEXT    NOT NULL DEFAULT '{}',
    sealed_result_blob     BLOB,
    result_bytes           INTEGER NOT NULL DEFAULT 0,
    result_truncated       INTEGER NOT NULL DEFAULT 0 CHECK (result_truncated IN (0, 1)),
    result_expired         INTEGER NOT NULL DEFAULT 0 CHECK (result_expired IN (0, 1)),
    deadline_at_ms         INTEGER NOT NULL,
    started_at_ms          INTEGER,
    finished_at_ms         INTEGER,
    created_at_ms          INTEGER NOT NULL,
    result_expires_at_ms   INTEGER NOT NULL,
    expires_at_ms          INTEGER NOT NULL,
    UNIQUE (caller_principal_id, request_id),
    CHECK ((invoke_kind = 'profile' AND profile_id IS NOT NULL AND profile_version IS NOT NULL)
        OR (invoke_kind = 'tool_test' AND profile_id IS NULL AND profile_version IS NULL)),
    CHECK ((executor_kind = 'node' AND node_id IS NOT NULL AND upstream_id IS NULL)
        OR (executor_kind = 'upstream' AND upstream_id IS NOT NULL AND node_id IS NULL)),
    CHECK ((sealed_result_blob IS NULL AND result_bytes = 0)
        OR (sealed_result_blob IS NOT NULL AND result_bytes = length(sealed_result_blob) AND result_bytes > 0))
);
CREATE INDEX idx_executions_caller_created ON executions(caller_principal_id, created_at_ms DESC);
CREATE INDEX idx_executions_created ON executions(created_at_ms DESC);
CREATE INDEX idx_executions_active_node ON executions(node_id, state) WHERE state IN ('accepted', 'running');
CREATE INDEX idx_executions_active_upstream ON executions(upstream_id, caller_principal_id) WHERE executor_kind = 'upstream' AND state IN ('accepted', 'running');
CREATE INDEX idx_executions_active_deadline ON executions(deadline_at_ms) WHERE state IN ('accepted', 'running');
CREATE INDEX idx_executions_result_expires ON executions(result_expires_at_ms, execution_id) WHERE sealed_result_blob IS NOT NULL;
CREATE INDEX idx_executions_expires ON executions(expires_at_ms);


CREATE TABLE events (
    seq                      INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id                 TEXT    NOT NULL UNIQUE,
    kind                     TEXT    NOT NULL,
    aggregate_type           TEXT    NOT NULL,
    aggregate_id             TEXT    NOT NULL,
    actor_id                 TEXT    NOT NULL,
    owner_principal_id       TEXT,
    agent_owner_principal_id TEXT,
    node_id                  TEXT,
    profile_id               TEXT,
    payload_json             TEXT    NOT NULL DEFAULT '{}',
    created_at_ms            INTEGER NOT NULL,
    expires_at_ms            INTEGER NOT NULL
);
