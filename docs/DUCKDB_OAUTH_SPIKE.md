# DuckDB CLI OAuth Authentication Spike

## Overview

This document explores how to integrate oauth.do authentication with the native DuckDB CLI, allowing users to query authenticated cloud endpoints directly from DuckDB.

## DuckDB Authentication Methods

DuckDB 1.1+ supports HTTP authentication via the Secrets Manager:

```sql
-- Bearer token authentication
CREATE SECRET http_auth (
    TYPE http,
    BEARER_TOKEN 'your-oauth-token'
);

-- Custom headers (alternative)
CREATE SECRET my_api (
    TYPE HTTP,
    EXTRA_HTTP_HEADERS MAP {
        'Authorization': 'Bearer your-oauth-token',
        'X-API-Key': 'your-api-key'
    }
);
```

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Workflow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. oauth.do login    ─────►  Stores token in keychain     │
│                                                             │
│  2. duckdb            ─────►  Starts DuckDB CLI            │
│                                                             │
│  3. .load oauth.do    ─────►  DuckDB extension loads       │
│                                oauth.do token and creates   │
│                                HTTP secret automatically    │
│                                                             │
│  4. SELECT * FROM     ─────►  Queries authenticated API    │
│     read_json('https://api.ducktail.do/query?sql=...')     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Options

### Option 1: Shell Script Wrapper (Quick Win)

Create a `duckdb-auth` script that:
1. Gets token from oauth.do CLI
2. Passes it to DuckDB as a variable
3. Creates the secret on startup

```bash
#!/bin/bash
# duckdb-auth - DuckDB with oauth.do authentication

TOKEN=$(oauth.do token 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo "Not logged in. Running: oauth.do login"
  oauth.do login
  TOKEN=$(oauth.do token)
fi

duckdb -cmd "CREATE SECRET oauth_do (TYPE http, BEARER_TOKEN '$TOKEN');" "$@"
```

### Option 2: DuckDB Extension (Best UX)

Create a DuckDB extension that:
1. Reads token from oauth.do keychain storage
2. Automatically creates HTTP secrets
3. Provides helper functions

```sql
-- Load the extension
INSTALL oauth_do FROM community;
LOAD oauth_do;

-- Login (opens browser)
CALL oauth_do_login();

-- Set up authentication automatically
CALL oauth_do_setup();
-- Creates: SECRET oauth_do (TYPE http, BEARER_TOKEN 'xxx')

-- Query authenticated endpoint
SELECT * FROM read_json('https://api.ducktail.do/query?sql=SELECT 1');
```

### Option 3: DuckDB Init File (Simple)

Use `.duckdbrc` to auto-configure on startup:

```sql
-- ~/.duckdbrc
.shell oauth.do token > /tmp/oauth_token.txt
CREATE SECRET oauth_do AS (
    TYPE http,
    BEARER_TOKEN (SELECT * FROM read_text('/tmp/oauth_token.txt'))
);
```

## Recommended Approach

**Phase 1: Shell Wrapper** (Immediate)
- Create `duckdb-auth` wrapper script
- Include in oauth.do npm package
- Works today with no DuckDB modifications

**Phase 2: DuckDB Extension** (Future)
- Build proper extension for best UX
- Handle token refresh
- Support multiple providers

## Example Usage

```bash
# Login once
$ oauth.do login

# Use authenticated DuckDB
$ duckdb-auth mydata.db
D SELECT * FROM read_json('https://api.ducktail.do/tables');
┌────────────┬───────────┐
│   name     │   rows    │
├────────────┼───────────┤
│ events     │   10234   │
│ users      │     892   │
└────────────┴───────────┘

# Or query cloud DuckDB directly
D ATTACH 'https://ducktail.do/db/analytics' AS cloud;
D SELECT count(*) FROM cloud.events;
```

## Security Considerations

1. **Token Storage**: Use keychain/keytar when available
2. **Token Refresh**: Handle expiration gracefully
3. **Scope Limits**: Request minimal scopes for CLI usage
4. **Audit Logging**: Log CLI queries for security auditing

## API Endpoint Requirements

The ducktail.do worker needs these endpoints:

```
GET  /db/:database          - Attach as read-only DuckDB
POST /query                 - Execute SQL query
GET  /tables                - List available tables
GET  /schema/:table         - Get table schema
```

All endpoints require `Authorization: Bearer <token>` header.

## Next Steps

1. [ ] Create `duckdb-auth` wrapper in oauth.do package
2. [ ] Add `/db/:database` endpoint to ducktail worker
3. [ ] Test ATTACH with httpfs extension
4. [ ] Document usage in README
5. [ ] Consider DuckDB extension for Phase 2

## References

- [DuckDB HTTP(S) Support](https://duckdb.org/docs/stable/core_extensions/httpfs/https)
- [DuckDB Secrets Manager](https://duckdb.org/docs/configuration/secrets_manager.html)
- [DuckDB HTTP Server Extension](https://duckdb.org/community_extensions/extensions/httpserver)
- [oauth.do CLI Documentation](https://oauth.do)
