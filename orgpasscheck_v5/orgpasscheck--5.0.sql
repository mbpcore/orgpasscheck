-- orgpasscheck--5.0.sql
--
-- Enterprise Password Policy Enforcement Extension for PostgreSQL 16+
--
-- Author:   Md. Masum Billah <mbpcore@gmail.com>
-- Version:  5.0
-- License:  PostgreSQL License
--
-- Description:
--   Full install script.  Run after adding shared_preload_libraries = 'orgpasscheck'
--   to postgresql.conf and restarting PostgreSQL.
--
--   CREATE SCHEMA orgpasscheck;
--   CREATE EXTENSION orgpasscheck;

-- Version guard: require PostgreSQL 16 or later
-- ============================================================

DO $$
BEGIN
    IF current_setting('server_version_num')::int < 160000 THEN
        RAISE EXCEPTION
            'orgpasscheck 5.0 requires PostgreSQL 16 or later. '
            'Current version: %', current_setting('server_version');
    END IF;
END $$;

-- ============================================================
-- Core Storage Layer
-- ============================================================

CREATE TABLE IF NOT EXISTS orgpasscheck.password_history (
    seq           BIGSERIAL    PRIMARY KEY,
    username      TEXT         NOT NULL,
    password_hash TEXT         NOT NULL,
    salt          TEXT         NOT NULL,
    changed_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ph_username_seq
    ON orgpasscheck.password_history (username, seq DESC);

CREATE INDEX IF NOT EXISTS idx_ph_username_changed
    ON orgpasscheck.password_history (username, changed_at DESC);

-- ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS orgpasscheck.password_dictionary (
    id         BIGSERIAL    PRIMARY KEY,
    word       TEXT         NOT NULL UNIQUE,
    category   TEXT,
    added_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pd_word
    ON orgpasscheck.password_dictionary (word);

-- Seed with the OWASP / NIST most-common-passwords shortlist.
-- Add your own with: INSERT INTO orgpasscheck.password_dictionary (word, category)
INSERT INTO orgpasscheck.password_dictionary (word, category) VALUES
    ('password',  'common'),
    ('passw0rd',  'common'),
    ('password1', 'common'),
    ('password123','common'),
    ('123456',    'numeric'),
    ('12345678',  'numeric'),
    ('123456789', 'numeric'),
    ('1234567890','numeric'),
    ('qwerty',    'keyboard'),
    ('qwertyuiop','keyboard'),
    ('asdfgh',    'keyboard'),
    ('zxcvbn',    'keyboard'),
    ('qazwsx',    'keyboard'),
    ('abc123',    'common'),
    ('letmein',   'common'),
    ('welcome',   'common'),
    ('admin',     'common'),
    ('administrator','common'),
    ('login',     'common'),
    ('monkey',    'common'),
    ('dragon',    'common'),
    ('master',    'common'),
    ('hello',     'common'),
    ('freedom',   'common'),
    ('whatever',  'common'),
    ('trustno1',  'common'),
    ('iloveyou',  'common'),
    ('sunshine',  'common'),
    ('princess',  'common'),
    ('shadow',    'common'),
    ('superman',  'common'),
    ('batman',    'common'),
    ('michael',   'common'),
    ('jessica',   'common'),
    ('baseball',  'common'),
    ('football',  'common'),
    ('soccer',    'common'),
    ('hockey',    'common'),
    ('access',    'common'),
    ('secret',    'common'),
    ('computer',  'common'),
    ('internet',  'common')
ON CONFLICT (word) DO NOTHING;

-- ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS orgpasscheck.password_blacklist (
    id               BIGSERIAL    PRIMARY KEY,
    blacklisted_word TEXT         NOT NULL UNIQUE,
    reason           TEXT,
    added_by         TEXT         NOT NULL DEFAULT current_user,
    added_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pbl_word
    ON orgpasscheck.password_blacklist (blacklisted_word);


-- ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS orgpasscheck.password_expiry_exemption (
    id          BIGSERIAL    PRIMARY KEY,
    username    TEXT         NOT NULL UNIQUE,
    reason      TEXT,
    added_by    TEXT         NOT NULL DEFAULT current_user,
    added_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    active      BOOLEAN      NOT NULL DEFAULT true,
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pee_username
    ON orgpasscheck.password_expiry_exemption (username);

CREATE INDEX IF NOT EXISTS idx_pee_active
    ON orgpasscheck.password_expiry_exemption (active);

-- ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS orgpasscheck.ddl_audit_log (
    id           BIGSERIAL    PRIMARY KEY,
    rolname      TEXT         NOT NULL,
    command_tag  TEXT         NOT NULL,
    issued_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    issued_by    TEXT         NOT NULL DEFAULT current_user,
    query_text   TEXT
);

CREATE INDEX IF NOT EXISTS idx_dal_rolname_time
    ON orgpasscheck.ddl_audit_log (rolname, issued_at DESC);

-- ============================================================
-- Monitoring Views
-- ============================================================

CREATE OR REPLACE VIEW orgpasscheck.user_password_status AS
SELECT
    r.rolname                                               AS username,
    r.rolvaliduntil                                         AS expires_at,
    CASE
        WHEN r.rolvaliduntil IS NULL
          OR r.rolvaliduntil = 'infinity'::timestamptz      THEN 'no expiry'
        WHEN r.rolvaliduntil < now()                        THEN 'EXPIRED'
        WHEN r.rolvaliduntil < now() + interval '14 days'  THEN 'expiring soon'
        ELSE                                                     'ok'
    END                                                     AS status,
    CASE
        WHEN r.rolvaliduntil IS NULL
          OR r.rolvaliduntil = 'infinity'::timestamptz      THEN NULL
        ELSE EXTRACT(DAY FROM (r.rolvaliduntil - now()))::integer
    END                                                     AS days_remaining,
    h.last_changed,
    h.history_count,
    h.days_since_change,
    e.active                                                AS expiry_exempt,
    e.reason                                                AS exemption_reason
FROM pg_roles r
LEFT JOIN (
    SELECT
        username,
        MAX(changed_at)                                              AS last_changed,
        COUNT(*)                                                     AS history_count,
        EXTRACT(DAY FROM (now() - MAX(changed_at)))::integer        AS days_since_change
    FROM orgpasscheck.password_history
    GROUP BY username
) h ON h.username = r.rolname
LEFT JOIN orgpasscheck.password_expiry_exemption e
       ON e.username = r.rolname AND e.active = true
WHERE r.rolcanlogin = true
ORDER BY
    CASE
        WHEN r.rolvaliduntil < now()                       THEN 0
        WHEN r.rolvaliduntil < now() + interval '14 days' THEN 1
        WHEN r.rolvaliduntil IS NULL
          OR r.rolvaliduntil = 'infinity'::timestamptz   THEN 3
        ELSE                                                  2
    END,
    r.rolname;

-- ---------------------------------------------------------------

CREATE OR REPLACE VIEW orgpasscheck.expired_passwords AS
SELECT
    rolname                                                          AS username,
    rolvaliduntil                                                    AS expired_at,
    EXTRACT(DAY FROM (now() - rolvaliduntil))::integer              AS days_overdue
FROM pg_roles
WHERE rolcanlogin = true
  AND rolvaliduntil IS NOT NULL
  AND rolvaliduntil != 'infinity'::timestamptz
  AND rolvaliduntil < now()
  AND NOT EXISTS (
      SELECT 1
      FROM orgpasscheck.password_expiry_exemption
      WHERE username = rolname
        AND active = true
        AND (expires_at IS NULL OR expires_at > now())
  )
ORDER BY rolvaliduntil;

-- ---------------------------------------------------------------


-- ---------------------------------------------------------------

CREATE OR REPLACE VIEW orgpasscheck.rotation_report AS
-- Thresholds are derived from orgpasscheck.expiry_days GUC so that the
-- rotation status labels always reflect the active policy.
--   overdue       : days_since_change > expiry_days
--   due soon      : days_since_change > expiry_days * 0.75
--   approaching   : days_since_change > expiry_days * 0.60
SELECT
    r.rolname                                               AS username,
    h.last_changed,
    h.days_since_change,
    CASE
        WHEN h.days_since_change IS NULL                            THEN 'never set'
        WHEN h.days_since_change > v.expiry_days                   THEN 'overdue'
        WHEN h.days_since_change > (v.expiry_days * 0.75)::int     THEN 'due soon'
        WHEN h.days_since_change > (v.expiry_days * 0.60)::int     THEN 'approaching due'
        ELSE                                                             'recent'
    END                                                     AS rotation_status,
    v.expiry_days                                           AS policy_expiry_days,
    r.rolvaliduntil                                         AS expires_at,
    CASE
        WHEN r.rolvaliduntil IS NULL
          OR r.rolvaliduntil = 'infinity'::timestamptz      THEN 'no expiry'
        WHEN r.rolvaliduntil < now()                        THEN 'EXPIRED'
        WHEN r.rolvaliduntil < now() + interval '14 days'  THEN 'expiring soon'
        ELSE                                                     'ok'
    END                                                     AS expiry_status,
    e.active                                                AS expiry_exempt
FROM pg_roles r
CROSS JOIN (
    SELECT current_setting('orgpasscheck.expiry_days')::int AS expiry_days
) v
LEFT JOIN (
    SELECT
        username,
        MAX(changed_at)                                              AS last_changed,
        EXTRACT(DAY FROM (now() - MAX(changed_at)))::integer        AS days_since_change
    FROM orgpasscheck.password_history
    GROUP BY username
) h ON h.username = r.rolname
LEFT JOIN orgpasscheck.password_expiry_exemption e
       ON e.username = r.rolname AND e.active = true
WHERE r.rolcanlogin = true
ORDER BY h.days_since_change DESC NULLS LAST;

-- ---------------------------------------------------------------

CREATE OR REPLACE VIEW orgpasscheck.version_info AS
SELECT
    '5.0'                                                           AS extension_version,
    current_setting('server_version')                               AS postgres_version,
    current_setting('server_version_num')::int                     AS postgres_version_num,
    'Native C Hook (check_password_hook) — PostgreSQL 16+'::text   AS operation_mode;

-- ---------------------------------------------------------------

CREATE OR REPLACE VIEW orgpasscheck.policy_summary AS
-- Live snapshot of all active orgpasscheck GUC settings.
-- Useful for operators to audit the current policy without querying pg_settings.
-- Usage: SELECT * FROM orgpasscheck.policy_summary;
SELECT
    current_setting('orgpasscheck.min_length')::int              AS min_length,
    current_setting('orgpasscheck.min_upper')::int               AS min_upper,
    current_setting('orgpasscheck.min_lower')::int               AS min_lower,
    current_setting('orgpasscheck.min_digit')::int               AS min_digit,
    current_setting('orgpasscheck.min_special')::int             AS min_special,
    current_setting('orgpasscheck.require_mixed_case')::bool     AS require_mixed_case,
    current_setting('orgpasscheck.require_sequence_check')::bool AS require_seq_check,
    current_setting('orgpasscheck.reject_username')::bool        AS reject_username,
    current_setting('orgpasscheck.similarity_check')::bool       AS similarity_check,
    current_setting('orgpasscheck.similarity_threshold')::int    AS similarity_threshold,
    current_setting('orgpasscheck.dictionary_check')::bool       AS dictionary_check,
    current_setting('orgpasscheck.blacklist_check')::bool        AS blacklist_check,
    current_setting('orgpasscheck.reuse_history')::int           AS reuse_history,
    current_setting('orgpasscheck.min_age_days')::int            AS min_age_days,
    current_setting('orgpasscheck.expiry_days')::int             AS expiry_days,
    current_setting('orgpasscheck.enforce_expiry')::bool         AS enforce_expiry,
    current_setting('orgpasscheck.allow_no_expiry_users')::bool  AS allow_no_expiry_users;

-- ============================================================
-- Hash Verification
-- ============================================================

-- verify_password_hash
--   Called from the C hook via SPI for history comparison.
--   Uses sha256() builtin (PG13+) — no pgcrypto dependency.
--   SECURITY DEFINER so the hook (running as superuser) can execute it;
--   PUBLIC execute is explicitly revoked below.
CREATE OR REPLACE FUNCTION orgpasscheck.verify_password_hash(
    p_password  TEXT,
    p_salt      TEXT,
    p_stored    TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
    -- Note: TEXT = comparison is not constant-time. This is acceptable for
    -- history checks where no timing oracle is exposed to end users.
    SELECT encode(sha256((p_salt || p_password)::bytea), 'hex') = p_stored;
$$;

-- record_password_history
--   Manual admin helper — e.g. to seed history when migrating from another
--   policy system.  The C hook handles history recording automatically for
--   every CREATE/ALTER ROLE; this function is NOT called by the hook.
CREATE OR REPLACE FUNCTION orgpasscheck.record_password_history(
    p_username  TEXT,
    p_password  TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_salt TEXT;
    v_hash TEXT;
BEGIN
    -- gen_random_uuid() uses pg_strong_random → /dev/urandom (PG 16 builtin)
    v_salt := replace(gen_random_uuid()::text, '-', '');
    v_hash := encode(sha256((v_salt || p_password)::bytea), 'hex');

    INSERT INTO orgpasscheck.password_history (username, password_hash, salt)
    VALUES (p_username, v_hash, v_salt);
END;
$$;

-- ============================================================
-- Secure API Wrapper Functions
-- ============================================================

-- create_user
--   Safe wrapper around CREATE ROLE that enforces expiry policy and
--   records an audit log entry.  The C hook fires on the underlying
--   DDL and handles all password policy checks + history recording.
CREATE OR REPLACE FUNCTION orgpasscheck.create_user(
    p_username    TEXT,
    p_password    TEXT,
    p_login       BOOLEAN  DEFAULT true,
    p_superuser   BOOLEAN  DEFAULT false,
    p_expiry_days INTEGER  DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_expiry          TIMESTAMPTZ;
    v_login_str       TEXT := CASE WHEN p_login     THEN 'LOGIN'     ELSE 'NOLOGIN'     END;
    v_super_str       TEXT := CASE WHEN p_superuser THEN 'SUPERUSER' ELSE 'NOSUPERUSER' END;
    v_sql             TEXT;
    v_guc_expiry      INT;
    v_allow_no_expiry BOOLEAN;
BEGIN
    -- Validate username format to prevent SQL injection via format()
    IF p_username !~ '^[a-zA-Z_][a-zA-Z0-9_$]*$' THEN
        RAISE EXCEPTION 'orgpasscheck: invalid username "%". '
            'Must start with a letter or underscore and contain only '
            'letters, digits, underscores, or dollar signs.', p_username;
    END IF;

    BEGIN
        v_guc_expiry := current_setting('orgpasscheck.expiry_days')::int;
    EXCEPTION WHEN OTHERS THEN
        v_guc_expiry := 45;
    END;

    BEGIN
        v_allow_no_expiry := current_setting('orgpasscheck.allow_no_expiry_users')::boolean;
    EXCEPTION WHEN OTHERS THEN
        v_allow_no_expiry := false;
    END;

    -- Resolve effective expiry
    IF p_expiry_days IS NOT NULL AND p_expiry_days = 0 THEN
        IF NOT v_allow_no_expiry THEN
            RAISE EXCEPTION
                'orgpasscheck: no-expiry users are disabled '
                '(orgpasscheck.allow_no_expiry_users = off). '
                'Pass a positive p_expiry_days or enable the setting.';
        END IF;
        -- No expiry granted
        v_sql := format('CREATE ROLE %I %s %s PASSWORD %L',
                        p_username, v_login_str, v_super_str, p_password);
    ELSIF p_expiry_days IS NOT NULL AND p_expiry_days > 0 THEN
        v_expiry := now() + (p_expiry_days || ' days')::interval;
        v_sql := format('CREATE ROLE %I %s %s PASSWORD %L VALID UNTIL %L',
                        p_username, v_login_str, v_super_str, p_password, v_expiry);
    ELSE
        -- Use GUC default
        IF v_guc_expiry = 0 THEN
            IF NOT v_allow_no_expiry THEN
                -- Misconfiguration guard: force 45-day default
                RAISE WARNING
                    'orgpasscheck: expiry_days = 0 but allow_no_expiry_users = off. '
                    'Defaulting to 45-day expiry.';
                v_guc_expiry := 45;
            END IF;
        END IF;
        IF v_guc_expiry = 0 THEN
            v_sql := format('CREATE ROLE %I %s %s PASSWORD %L',
                            p_username, v_login_str, v_super_str, p_password);
        ELSE
            v_expiry := now() + (v_guc_expiry || ' days')::interval;
            v_sql := format('CREATE ROLE %I %s %s PASSWORD %L VALID UNTIL %L',
                            p_username, v_login_str, v_super_str, p_password, v_expiry);
        END IF;
    END IF;

    EXECUTE v_sql;

    INSERT INTO orgpasscheck.ddl_audit_log (rolname, command_tag, query_text)
    VALUES (p_username, 'CREATE ROLE',
            format('orgpasscheck.create_user(%L, ...)', p_username));

    -- Register exemption if no-expiry was granted
    IF p_expiry_days = 0 AND v_allow_no_expiry THEN
        INSERT INTO orgpasscheck.password_expiry_exemption (username, reason)
        VALUES (p_username, 'Created with no expiry (p_expiry_days = 0)')
        ON CONFLICT (username) DO UPDATE
            SET active   = true,
                added_at = now(),
                reason   = EXCLUDED.reason;
    END IF;

    IF v_expiry IS NOT NULL THEN
        RAISE NOTICE 'User "%" created. Password expires on %.', p_username, v_expiry::date;
    ELSE
        RAISE NOTICE 'User "%" created with no password expiry.', p_username;
    END IF;
END;
$$;

-- ---------------------------------------------------------------

-- change_password
--   Safe wrapper around ALTER ROLE ... PASSWORD that enforces
--   authorization, expiry policy, and audit logging.
CREATE OR REPLACE FUNCTION orgpasscheck.change_password(
    p_username    TEXT,
    p_password    TEXT,
    p_expiry_days INTEGER DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_expiry              TIMESTAMPTZ;
    v_sql                 TEXT;
    v_guc_expiry          INT;
    v_allow_no_expiry     BOOLEAN;
    v_is_exempt           BOOLEAN;
    v_target_is_superuser BOOLEAN;
BEGIN
    -- Validate username format (same rule as create_user)
    IF p_username !~ '^[a-zA-Z_][a-zA-Z0-9_$]*$' THEN
        RAISE EXCEPTION 'orgpasscheck: invalid username "%". '
            'Must start with a letter or underscore and contain only '
            'letters, digits, underscores, or dollar signs.', p_username;
    END IF;

    -- Authorization: non-superusers may only change their own password
    -- unless they are orgpasscheck_admin members.
    SELECT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = p_username AND rolsuper = true
    ) INTO v_target_is_superuser;

    IF v_target_is_superuser AND current_setting('is_superuser') <> 'on' THEN
        RAISE EXCEPTION
            'orgpasscheck: only superusers may change a superuser''s password.';
    END IF;

    IF session_user <> p_username
       AND current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION
            'orgpasscheck: permission denied. You may only change your own '
            'password unless you are a superuser or orgpasscheck_admin member.';
    END IF;

    BEGIN
        v_guc_expiry := current_setting('orgpasscheck.expiry_days')::int;
    EXCEPTION WHEN OTHERS THEN
        v_guc_expiry := 45;
    END;

    BEGIN
        v_allow_no_expiry := current_setting('orgpasscheck.allow_no_expiry_users')::boolean;
    EXCEPTION WHEN OTHERS THEN
        v_allow_no_expiry := false;
    END;

    SELECT active INTO v_is_exempt
    FROM orgpasscheck.password_expiry_exemption
    WHERE username = p_username AND active = true;

    -- Determine expiry for the ALTER ROLE
    IF v_is_exempt AND (p_expiry_days IS NULL OR p_expiry_days = 0) THEN
        v_sql := format('ALTER ROLE %I PASSWORD %L VALID UNTIL ''infinity''',
                        p_username, p_password);
        RAISE NOTICE 'User "%" is expiry-exempt; keeping no expiry.', p_username;

    ELSIF p_expiry_days IS NOT NULL AND p_expiry_days = 0 THEN
        IF NOT v_allow_no_expiry THEN
            RAISE EXCEPTION
                'orgpasscheck: no-expiry users are disabled '
                '(orgpasscheck.allow_no_expiry_users = off).';
        END IF;
        -- Only superusers and orgpasscheck_admin may grant permanent no-expiry.
        -- Without this guard, any user could call change_password(self, pw, 0)
        -- to grant themselves a permanent password when allow_no_expiry_users = on.
        IF current_setting('is_superuser') <> 'on'
           AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
            RAISE EXCEPTION
                'orgpasscheck: only superusers and orgpasscheck_admin members '
                'may grant no-expiry passwords.';
        END IF;
        v_sql := format('ALTER ROLE %I PASSWORD %L VALID UNTIL ''infinity''',
                        p_username, p_password);

    ELSIF p_expiry_days IS NOT NULL AND p_expiry_days > 0 THEN
        v_expiry := now() + (p_expiry_days || ' days')::interval;
        v_sql := format('ALTER ROLE %I PASSWORD %L VALID UNTIL %L',
                        p_username, p_password, v_expiry);

    ELSE
        -- Use GUC default
        IF v_guc_expiry = 0 AND NOT v_allow_no_expiry THEN
            RAISE WARNING
                'orgpasscheck: expiry_days = 0 but allow_no_expiry_users = off. '
                'Defaulting to 45-day expiry.';
            v_guc_expiry := 45;
        END IF;
        IF v_guc_expiry = 0 THEN
            v_sql := format('ALTER ROLE %I PASSWORD %L VALID UNTIL ''infinity''',
                            p_username, p_password);
        ELSE
            v_expiry := now() + (v_guc_expiry || ' days')::interval;
            v_sql := format('ALTER ROLE %I PASSWORD %L VALID UNTIL %L',
                            p_username, p_password, v_expiry);
        END IF;
    END IF;

    EXECUTE v_sql;

    INSERT INTO orgpasscheck.ddl_audit_log (rolname, command_tag, query_text)
    VALUES (p_username, 'ALTER ROLE',
            format('orgpasscheck.change_password(%L, ...)', p_username));

    -- Sync exemption table
    IF p_expiry_days = 0 AND v_allow_no_expiry THEN
        INSERT INTO orgpasscheck.password_expiry_exemption (username, reason)
        VALUES (p_username, 'No expiry set via change_password()')
        ON CONFLICT (username) DO UPDATE
            SET active   = true,
                added_at = now(),
                reason   = EXCLUDED.reason;
    ELSIF p_expiry_days IS NOT NULL AND p_expiry_days > 0 THEN
        DELETE FROM orgpasscheck.password_expiry_exemption WHERE username = p_username;
    END IF;

    IF v_expiry IS NOT NULL THEN
        RAISE NOTICE 'Password for "%" updated. New expiry: %.', p_username, v_expiry::date;
    ELSE
        RAISE NOTICE 'Password for "%" updated with no expiry.', p_username;
    END IF;
END;
$$;

-- ============================================================
-- Exemption Management
-- ============================================================

CREATE OR REPLACE FUNCTION orgpasscheck.add_expiry_exemption(
    p_username   TEXT,
    p_reason     TEXT        DEFAULT NULL,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to grant expiry exemptions. '
            'Only superusers and orgpasscheck_admin members may add exemptions.';
    END IF;

    INSERT INTO orgpasscheck.password_expiry_exemption (username, reason, expires_at)
    VALUES (p_username, p_reason, p_expires_at)
    ON CONFLICT (username) DO UPDATE
        SET active     = true,
            reason     = COALESCE(EXCLUDED.reason, orgpasscheck.password_expiry_exemption.reason),
            expires_at = COALESCE(EXCLUDED.expires_at, orgpasscheck.password_expiry_exemption.expires_at),
            added_at   = now();

    EXECUTE format('ALTER ROLE %I VALID UNTIL ''infinity''', p_username);
    RAISE NOTICE 'User "%" added to expiry exemption.', p_username;
END;
$$;

-- ---------------------------------------------------------------

CREATE OR REPLACE FUNCTION orgpasscheck.remove_expiry_exemption(
    p_username TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to remove expiry exemptions. '
            'Only superusers and orgpasscheck_admin members may remove exemptions.';
    END IF;

    DELETE FROM orgpasscheck.password_expiry_exemption WHERE username = p_username;

    IF NOT FOUND THEN
        RAISE NOTICE 'User "%" was not in the expiry exemption list.', p_username;
    ELSE
        RAISE NOTICE 'User "%" removed from expiry exemption.', p_username;
    END IF;
END;
$$;

-- ---------------------------------------------------------------

CREATE OR REPLACE FUNCTION orgpasscheck.list_expiry_exemptions()
RETURNS TABLE (
    username   TEXT,
    reason     TEXT,
    added_by   TEXT,
    added_at   TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    active     BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied. '
            'Only superusers and orgpasscheck_admin members may list expiry exemptions.';
    END IF;

    RETURN QUERY
        SELECT e.username, e.reason, e.added_by, e.added_at, e.expires_at, e.active
        FROM   orgpasscheck.password_expiry_exemption e
        ORDER  BY e.username;
END;
$$;

-- ============================================================
-- Blacklist Management
-- ============================================================

CREATE OR REPLACE FUNCTION orgpasscheck.add_blacklist(
    p_pattern TEXT,
    p_reason  TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to modify the blacklist.';
    END IF;

    -- Store lowercase: the C hook compares against lower_pw.
    -- Escape LIKE metacharacters (% and _) so a blacklist word like
    -- 'p%ss' only matches the literal string 'p%ss', not 'pass' or 'p4ss'.
    -- The C hook query uses ESCAPE '\' to honour these escapes.
    INSERT INTO orgpasscheck.password_blacklist (blacklisted_word, reason)
    VALUES (
        replace(replace(replace(lower(p_pattern), '\', '\\'), '%', '\%'), '_', '\_'),
        p_reason
    )
    ON CONFLICT (blacklisted_word) DO UPDATE
        SET reason   = EXCLUDED.reason,
            added_at = now(),
            added_by = current_user;

    RAISE NOTICE 'Pattern "%" added to blacklist.', lower(p_pattern);
END;
$$;

-- ---------------------------------------------------------------

CREATE OR REPLACE FUNCTION orgpasscheck.remove_blacklist(
    p_pattern TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_escaped TEXT;
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to modify the blacklist.';
    END IF;

    -- Apply the same escaping used by add_blacklist so the lookup matches
    -- what is actually stored (backslash first, then % and _).
    v_escaped := replace(replace(replace(lower(p_pattern), '\', '\\'), '%', '\%'), '_', '\_');

    DELETE FROM orgpasscheck.password_blacklist
    WHERE blacklisted_word = v_escaped;

    IF NOT FOUND THEN
        RAISE NOTICE 'Pattern "%" was not found in the blacklist.', lower(p_pattern);
    ELSE
        RAISE NOTICE 'Pattern "%" removed from blacklist.', lower(p_pattern);
    END IF;
END;
$$;

-- ============================================================
-- History Maintenance
-- ============================================================

CREATE OR REPLACE FUNCTION orgpasscheck.purge_user_history(
    p_username TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_count INT;
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to purge password history.';
    END IF;

    DELETE FROM orgpasscheck.password_history WHERE username = p_username;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RAISE NOTICE 'Deleted % history row(s) for user "%".', v_count, p_username;
    RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------

-- purge_old_history
--   Trims ALL users' history to at most reuse_history rows.
--   The C hook prunes per-user automatically on each password change,
--   so this function is mainly useful for one-time cleanup after
--   lowering orgpasscheck.reuse_history.
CREATE OR REPLACE FUNCTION orgpasscheck.purge_old_history()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_keep  INT;
    v_count INT;
BEGIN
    BEGIN
        v_keep := current_setting('orgpasscheck.reuse_history')::int;
    EXCEPTION WHEN OTHERS THEN
        v_keep := 5;
    END;

    IF v_keep <= 0 THEN
        RETURN 0;
    END IF;

    DELETE FROM orgpasscheck.password_history
    WHERE seq NOT IN (
        SELECT seq
        FROM (
            SELECT seq,
                   ROW_NUMBER() OVER (PARTITION BY username ORDER BY seq DESC) AS rn
            FROM orgpasscheck.password_history
        ) ranked
        WHERE rn <= v_keep
    );
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------



CREATE OR REPLACE FUNCTION orgpasscheck.purge_audit_log(
    p_older_than INTERVAL DEFAULT '1 year'
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = orgpasscheck, pg_catalog
AS $$
DECLARE
    v_count INT;
BEGIN
    IF current_setting('is_superuser') <> 'on'
       AND NOT pg_has_role(session_user, 'orgpasscheck_admin', 'USAGE') THEN
        RAISE EXCEPTION 'orgpasscheck: permission denied to purge audit log.';
    END IF;

    DELETE FROM orgpasscheck.ddl_audit_log
    WHERE issued_at < now() - p_older_than;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RAISE NOTICE 'Deleted % audit log row(s) older than %.', v_count, p_older_than;
    RETURN v_count;
END;
$$;

-- ============================================================
-- Role & Grant Layer
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orgpasscheck_admin') THEN
        CREATE ROLE orgpasscheck_admin NOLOGIN;
    END IF;
END $$;

GRANT USAGE  ON SCHEMA orgpasscheck TO orgpasscheck_admin;
GRANT SELECT, INSERT, UPDATE, DELETE
      ON ALL TABLES    IN SCHEMA orgpasscheck TO orgpasscheck_admin;
GRANT USAGE  ON ALL SEQUENCES IN SCHEMA orgpasscheck TO orgpasscheck_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA orgpasscheck TO orgpasscheck_admin;

-- ============================================================
-- Security: REVOKE PUBLIC execute on ALL SECURITY DEFINER functions.
--
-- Every function in this extension is SECURITY DEFINER (runs as the
-- superuser who installed it). Without explicit REVOKEs, any database
-- user can call them and abuse the elevated privilege — for example,
-- calling create_user() to create new roles without being a superuser.
--
-- We revoke from PUBLIC first, then grant back only to the roles that
-- legitimately need each function.
-- ============================================================

-- Internal functions — never callable by anyone except the C hook (via SPI)
REVOKE EXECUTE ON FUNCTION orgpasscheck.verify_password_hash(TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.record_password_history(TEXT, TEXT)    FROM PUBLIC;
-- record_password_history is internal-only; orgpasscheck_admin must not call it directly
-- to prevent history poisoning of other users' accounts.
REVOKE EXECUTE ON FUNCTION orgpasscheck.record_password_history(TEXT, TEXT)    FROM orgpasscheck_admin;

-- Admin-only functions — superuser or orgpasscheck_admin only
REVOKE EXECUTE ON FUNCTION orgpasscheck.create_user(TEXT, TEXT, BOOLEAN, BOOLEAN, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.add_expiry_exemption(TEXT, TEXT, TIMESTAMPTZ)      FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.remove_expiry_exemption(TEXT)                      FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.list_expiry_exemptions()                           FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.add_blacklist(TEXT, TEXT)                          FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.remove_blacklist(TEXT)                             FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.purge_user_history(TEXT)                           FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.purge_old_history()                                FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION orgpasscheck.purge_audit_log(INTERVAL)                          FROM PUBLIC;

-- change_password: every login role may change their OWN password.
-- The function enforces session_user = p_username internally so regular
-- users cannot change someone else's password.
-- Superusers and orgpasscheck_admin can change any user's password.
-- No REVOKE here — PUBLIC execute is intentional and safe.

-- Grant admin functions explicitly to orgpasscheck_admin
-- (already covered by GRANT EXECUTE ON ALL FUNCTIONS above, but explicit
--  grants survive future REVOKE ALL and make intent clear)
GRANT EXECUTE ON FUNCTION orgpasscheck.create_user(TEXT, TEXT, BOOLEAN, BOOLEAN, INTEGER) TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.add_expiry_exemption(TEXT, TEXT, TIMESTAMPTZ)      TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.remove_expiry_exemption(TEXT)                      TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.list_expiry_exemptions()                           TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.add_blacklist(TEXT, TEXT)                          TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.remove_blacklist(TEXT)                             TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.purge_user_history(TEXT)                           TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.purge_old_history()                                TO orgpasscheck_admin;
GRANT EXECUTE ON FUNCTION orgpasscheck.purge_audit_log(INTERVAL)                          TO orgpasscheck_admin;

-- Allow monitoring role to read views and tables
GRANT USAGE  ON SCHEMA orgpasscheck TO pg_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA orgpasscheck TO pg_monitor;
GRANT SELECT ON orgpasscheck.policy_summary TO PUBLIC;

-- ============================================================
-- Install notice
-- ============================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '╔══════════════════════════════════════════════════╗';
    RAISE NOTICE '║   orgpasscheck v5.0 installed successfully        ║';
    RAISE NOTICE '║   PostgreSQL %  ║', rpad(current_setting('server_version'), 27);
    RAISE NOTICE '╚══════════════════════════════════════════════════╝';
    RAISE NOTICE '';
    RAISE NOTICE 'Add to postgresql.conf:';
    RAISE NOTICE '  shared_preload_libraries = ''orgpasscheck''';
    RAISE NOTICE '';
    RAISE NOTICE 'Quick-start:';
    RAISE NOTICE '  SELECT orgpasscheck.create_user(''alice'', ''Str0ng!Pass#9'');';
    RAISE NOTICE '  SELECT * FROM orgpasscheck.user_password_status;';
END $$;
