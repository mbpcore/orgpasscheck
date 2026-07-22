# orgpasscheck

**Author:** Md. Masum Billah <mbpcore@gmail.com>

**Enterprise password policy enforcement extension for PostgreSQL 16+**

orgpasscheck intercepts every `CREATE ROLE` and `ALTER ROLE … PASSWORD` statement via PostgreSQL's native `check_password_hook` and enforces password complexity, history, dictionary, and blacklist policy — with no bypass possible through raw DDL. Password expiry requires use of the SQL wrapper functions.

---

## Features

| Check | Default | Configurable |
|-------|---------|-------------|
| Minimum length | 12 | ✓ |
| Uppercase / lowercase / digit / special counts | 1 each | ✓ |
| Sequential character run detection (`aaa`, `abc`, `321`) | on | ✓ |
| Username containment (case-insensitive) | on | ✓ |
| Levenshtein similarity to username | threshold 3 | ✓ |
| Dictionary word substring check | on | ✓ |
| Custom blacklist substring check | on | ✓ |
| Password reuse history | last 5 | ✓ |
| Minimum password age | 1 day | ✓ |
| Password expiry | 45 days | ✓ |
| Per-user expiry exemption | off | ✓ |

---

## Requirements

- PostgreSQL **16 or later**
- No external dependencies (no pgcrypto, no pg_trgm)
- C compiler and PostgreSQL development headers (`postgresql-server-dev-16`)

---

## Installation

```bash
# Clone
git clone https://github.com/mbpcore/orgpasscheck.git
cd orgpasscheck

# Build (adjust PG_CONFIG path as needed)
make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config
sudo make install

# Enable in postgresql.conf
echo "shared_preload_libraries = 'orgpasscheck'" >> /etc/postgresql/16/main/postgresql.conf
sudo systemctl restart postgresql

# Install extension (as superuser)
psql -U postgres -c "CREATE SCHEMA orgpasscheck;"
psql -U postgres -c "CREATE EXTENSION orgpasscheck;"
```


---

## Quick Start

```sql
-- Create a user (policy enforced automatically)
SELECT orgpasscheck.create_user('alice', 'Str0ng!Pass#9');

-- Change a password
SELECT orgpasscheck.change_password('alice', 'NewStr0ng!Pass#2');

-- Check all users' password status
SELECT * FROM orgpasscheck.user_password_status;

-- Add a company-specific blacklist pattern
SELECT orgpasscheck.add_blacklist('acmecorp', 'Company name prohibited in passwords');

-- Add a user to expiry exemption (service accounts, etc.)
SELECT orgpasscheck.add_expiry_exemption('svc_etl', 'Service account — rotated via Vault');
```

---

## Configuration (GUCs)

All settings are `PGC_SUSET` — changeable at runtime by a superuser.

```ini
# postgresql.conf or via ALTER SYSTEM / SET

# Complexity
orgpasscheck.min_length           = 12    # 0–128
orgpasscheck.min_upper            = 1     # 0–50
orgpasscheck.min_lower            = 1     # 0–50
orgpasscheck.min_digit            = 1     # 0–50
orgpasscheck.min_special          = 1     # 0–50
orgpasscheck.require_mixed_case   = on

# Pattern checks
orgpasscheck.require_sequence_check   = on
orgpasscheck.reject_username          = on
orgpasscheck.similarity_check         = on
orgpasscheck.similarity_threshold     = 3   # 0–20 (Levenshtein distance)

# Database checks
orgpasscheck.dictionary_check     = on
orgpasscheck.blacklist_check      = on

# History & lifecycle
orgpasscheck.reuse_history        = 5     # 0 = disabled
orgpasscheck.min_age_days         = 1     # 0 = disabled
orgpasscheck.expiry_days          = 45    # 0 = no expiry (needs allow_no_expiry_users=on)
orgpasscheck.enforce_expiry       = on
orgpasscheck.allow_no_expiry_users = off
```

---

## Schema & Tables

| Object | Description |
|--------|-------------|
| `orgpasscheck.password_history` | SHA-256 hashes + cryptographic salts of past passwords |
| `orgpasscheck.password_dictionary` | Common/weak words (substring-matched against new passwords) |
| `orgpasscheck.password_blacklist` | Admin-managed forbidden patterns |
| `orgpasscheck.password_expiry_exemption` | Per-user expiry bypass list |
| `orgpasscheck.ddl_audit_log` | CREATE/ALTER ROLE events from the SQL wrapper functions |

---

## Views

| View | Description |
|------|-------------|
| `user_password_status` | All login roles: expiry status, days remaining, last change |
| `expired_passwords` | Roles whose passwords have expired |
| `rotation_report` | Rotation health by user |
| `version_info` | Extension version and PostgreSQL version |

---

## Role Model

| Role | Purpose |
|------|---------|
| `orgpasscheck_admin` | Full read/write to orgpasscheck schema; can manage blacklists, exemptions, history |
| `pg_monitor` | Read-only access to all views and tables for monitoring tools |

---

## Security Notes

**`policy_summary` view is readable by PUBLIC.** This view exposes all policy parameters (min_length, reuse_history, etc.) to any database user. This is intentional for usability — users can see what is required before setting a password. In high-security environments, restrict with: `REVOKE SELECT ON orgpasscheck.policy_summary FROM PUBLIC;`

**Plaintext is required — permanently, by design — and `password_encryption` cannot change that.** orgpasscheck's complexity, dictionary, blacklist, and reuse-history checks all need the real password (to count characters, match substrings, and compare against salted history hashes). None of that is possible against an already-hashed value, so the hook rejects any password whose `password_type` isn't plaintext.

This is **not** a client misconfiguration you can fix with `password_encryption`. That setting only controls how the *server* encrypts a plaintext value it receives — it has no effect on the fact that, since PostgreSQL 10, `psql`'s `\password`, pgAdmin, and most drivers' "change password" helpers call `PQencryptPasswordConn()` and hash the password *client-side* before ever sending it, specifically so the plaintext never touches the wire or server logs. Because of this, **none of those tools can be used to set or change a password while orgpasscheck is installed** — the hook never receives plaintext from them, no matter how `password_encryption` is set.

Use the extension's own wrapper functions instead, which pass the plaintext password directly so the hook can evaluate it:

```sql
-- New user
SELECT orgpasscheck.create_user('alice', 'Str0ng!Pass#9');

-- Existing user changing their own (or, for an admin, another user's) password
SELECT orgpasscheck.change_password('alice', 'NewStr0ng!Pass#2');
```

Because the password appears as a plaintext SQL literal in these calls, treat them the same way you'd treat any other cleartext-password statement: avoid typing them where shell/`psql` history or `log_statement` would capture them (e.g. prefer piping from a file or an application layer over interactive typing), and rely on `orgpasscheck.ddl_audit_log` for a record of *that a change happened*, not of the password itself (it is never logged there).

If your organization cannot tolerate losing `\password`/pgAdmin/driver-based password changes, orgpasscheck is not compatible with that requirement — this is the same fundamental trade-off PostgreSQL's own `contrib/passwordcheck` module faces, except passwordcheck resolves it by silently skipping checks on non-plaintext input rather than blocking the change. orgpasscheck instead fails closed, so that no password can ever bypass policy — evaluate which trade-off fits your environment before adopting it.

**Password expiry is enforced by the SQL wrapper functions only.** The C hook enforces complexity, history, dictionary, blacklist, and minimum age. Password expiry (`VALID UNTIL`) is set by `orgpasscheck.create_user()` and `orgpasscheck.change_password()`. A superuser using raw DDL (`CREATE ROLE ... VALID UNTIL 'infinity'`) bypasses expiry enforcement. Restrict superuser access and use the wrapper functions for all user management.

**Salt quality.** Salts use `gen_random_uuid()` which calls `pg_strong_random()` internally, providing cryptographically random 122-bit salts with no pgcrypto dependency.

**History hashing.** Passwords in history are stored as `SHA-256(salt || plaintext)`. The plaintext is never persisted.
## Changes from v4.0

- `password_type` guard added — pre-hashed passwords now raise an error instead of silently passing all checks
- `PG_TRY/PG_CATCH` wraps all SPI work — SPI connection always closed on error
- Dynamic `palloc` for password buffers — no 512-byte stack truncation on long passwords  
- Levenshtein now uses lowercased strings — case-insensitive similarity detection
- Levenshtein integer overflow guard — inputs > 256 chars treated as maximally distant
- Dictionary check now uses substring matching (`LIKE '%' || word || '%'`) — `Welcome1!` now correctly fails
- Blacklist check now uses substring matching — patterns detected anywhere in the password
- History auto-pruned after each INSERT — table size bounded to `users × reuse_history` rows
- `username` NULL guard on every usage — no undefined behaviour on roles without a name
- Salt upgraded from `random()` (PRNG, ~106-bit) to `gen_random_uuid()` (CSPRNG, 122-bit)
- `expiry_days=0` + `allow_no_expiry_users=off` now raises an `EXCEPTION` instead of silently overriding
- `password_hint` column removed (was never populated)
- Expanded dictionary seed list (42 entries, up from 20)
- Upgrade script `` provided
- `META.json` added for PGXN publication
- GitHub Actions CI for PG 16 and 17
- PostgreSQL License file added

---

## License

[PostgreSQL License](LICENSE)
