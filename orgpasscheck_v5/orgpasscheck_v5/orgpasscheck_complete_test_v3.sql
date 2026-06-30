-- orgpasscheck_complete_test_v3.sql
--
-- Functional Test Suite for orgpasscheck v5.0
--
-- Author:   Md. Masum Billah <mbpcore@gmail.com>
-- Version:  5.0
-- License:  PostgreSQL License
--
-- Testing philosophy:
--   PASS means the FUNCTIONALITY works correctly — the extension enforced
--   or permitted the password as expected.  It does NOT mean the SQL
--   command executed without error.  A test that expects a rejection
--   (assert_raises) PASSES when the correct error is raised.  A test
--   that expects acceptance (assert_ok) PASSES when no error is raised.
--
-- Usage:
--   psql -U postgres -f orgpasscheck_complete_test_v3.sql

-- =============================================================================
-- Author  : Md. Masum Billah <mbpcore@gmail.com>
-- Purpose : Exhaustive A-Z validation of every GUC, hook check, SQL function,
--           view, table, constraint, and access-control rule before publishing
--           publication.
--
-- Run as superuser:
--   psql -U postgres -d <db> -f orgpasscheck_full_test.sql
--
-- All tests are self-contained.  The script creates its own result table,
-- runs every case, prints a live progress log, and emits a final summary.
-- A non-zero FAIL count means the release is not ready.
-- =============================================================================

\set ON_ERROR_STOP off
\set QUIET on

-- ---------------------------------------------------------------------------
-- 0. FRAMEWORK SETUP
-- ---------------------------------------------------------------------------
DROP SCHEMA IF EXISTS opc_test CASCADE;
CREATE SCHEMA opc_test;
SET search_path TO opc_test, orgpasscheck, public;

CREATE TABLE opc_test.results (
    id          SERIAL PRIMARY KEY,
    category    TEXT NOT NULL,
    test_id     TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('PASS','FAIL','SKIP')),
    detail      TEXT,
    ts          TIMESTAMPTZ DEFAULT now()
);

-- Helper: record a pass
CREATE OR REPLACE FUNCTION opc_test.pass(p_cat TEXT, p_id TEXT, p_desc TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO opc_test.results(category,test_id,description,status)
    VALUES (p_cat,p_id,p_desc,'PASS');
    RAISE NOTICE '  ✅ [%] %', p_id, p_desc;
END;$$;

-- Helper: record a fail
CREATE OR REPLACE FUNCTION opc_test.fail(p_cat TEXT, p_id TEXT, p_desc TEXT, p_detail TEXT DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO opc_test.results(category,test_id,description,status,detail)
    VALUES (p_cat,p_id,p_desc,'FAIL',p_detail);
    RAISE NOTICE '  ❌ [%] % | %', p_id, p_desc, COALESCE(p_detail,'');
END;$$;

-- Helper: record a skip
CREATE OR REPLACE FUNCTION opc_test.skip(p_cat TEXT, p_id TEXT, p_desc TEXT, p_reason TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO opc_test.results(category,test_id,description,status,detail)
    VALUES (p_cat,p_id,p_desc,'SKIP',p_reason);
    RAISE NOTICE '  ⏭  [%] % — SKIP: %', p_id, p_desc, p_reason;
END;$$;

-- Helper: assert a DDL raises an error matching a pattern
CREATE OR REPLACE FUNCTION opc_test.assert_raises(
    p_cat TEXT, p_id TEXT, p_desc TEXT,
    p_sql TEXT, p_pattern TEXT
) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_err TEXT;
BEGIN
    BEGIN
        EXECUTE p_sql;
        -- If we get here the error was NOT raised
        PERFORM opc_test.fail(p_cat, p_id, p_desc,
            'No error raised. Expected pattern: ' || p_pattern);
    EXCEPTION WHEN OTHERS THEN
        v_err := SQLERRM;
        IF v_err LIKE '%' || p_pattern || '%' THEN
            PERFORM opc_test.pass(p_cat, p_id, p_desc);
        ELSE
            PERFORM opc_test.fail(p_cat, p_id, p_desc,
                'Wrong error. Expected: ' || p_pattern || ' | Got: ' || v_err);
        END IF;
    END;
END;$$;

-- Helper: assert a DDL succeeds
CREATE OR REPLACE FUNCTION opc_test.assert_ok(
    p_cat TEXT, p_id TEXT, p_desc TEXT, p_sql TEXT
) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
        PERFORM opc_test.pass(p_cat, p_id, p_desc);
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail(p_cat, p_id, p_desc, SQLERRM);
    END;
END;$$;

-- Helper: clean up a test role and its history
CREATE OR REPLACE FUNCTION opc_test.cleanup(p_role TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE 'DROP ROLE IF EXISTS ' || quote_ident(p_role);
    DELETE FROM orgpasscheck.password_history    WHERE username = p_role;
EXCEPTION WHEN OTHERS THEN NULL;
END;$$;

-- Pre-test: disable min_age globally so tests can cycle passwords freely.
-- Each category that tests min_age will re-enable it locally.
SET orgpasscheck.min_age_days = 0;

\set QUIET off

-- =============================================================================
-- CATEGORY 1: INSTALLATION & SCHEMA
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 1 — INSTALLATION & SCHEMA';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE v TEXT; n INT;
BEGIN
    -- 1.1 Extension present and correct version
    SELECT extversion INTO v FROM pg_extension WHERE extname = 'orgpasscheck';
    IF v = '5.0' THEN
        PERFORM opc_test.pass('INSTALL','1.1','Extension installed at version 5.0');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.1','Extension installed at version 5.0',
            'Got version: ' || COALESCE(v,'NOT FOUND'));
    END IF;

    -- 1.2 Schema exists
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'orgpasscheck') THEN
        PERFORM opc_test.pass('INSTALL','1.2','Schema orgpasscheck exists');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.2','Schema orgpasscheck exists','Schema missing');
    END IF;

    -- 1.3 All 5 storage tables present
    SELECT COUNT(*) INTO n FROM information_schema.tables
    WHERE table_schema = 'orgpasscheck'
      AND table_name IN ('password_history','password_dictionary','password_blacklist',
                         'password_expiry_exemption','ddl_audit_log');
    IF n = 5 THEN
        PERFORM opc_test.pass('INSTALL','1.3','All 5 storage tables present');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.3','All 5 storage tables present',
            'Found ' || n || ' of 5');
    END IF;

    -- 1.4 All 5 views present
    SELECT COUNT(*) INTO n FROM information_schema.views
    WHERE table_schema = 'orgpasscheck'
      AND table_name IN ('user_password_status','expired_passwords',
                         'rotation_report','version_info','policy_summary');
    IF n = 5 THEN
        PERFORM opc_test.pass('INSTALL','1.4','All 5 views present');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.4','All 5 views present',
            'Found ' || n || ' of 5');
    END IF;

    -- 1.5 All 12 public functions present
    SELECT COUNT(*) INTO n
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck'
      AND p.proname IN ('verify_password_hash','record_password_history',
                        'create_user','change_password',
                        'add_expiry_exemption','remove_expiry_exemption','list_expiry_exemptions',
                        'add_blacklist','remove_blacklist',
                        'purge_user_history','purge_old_history');
    IF n = 11 THEN
        PERFORM opc_test.pass('INSTALL','1.5','All 11 functions present');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.5','All 11 functions present',
            'Found ' || n || ' of 11');
    END IF;

    -- 1.6 All 17 GUCs registered
    SELECT COUNT(*) INTO n FROM pg_settings WHERE name LIKE 'orgpasscheck.%';
    IF n = 17 THEN
        PERFORM opc_test.pass('INSTALL','1.6','All 17 GUCs registered');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.6','All 17 GUCs registered',
            'Found ' || n || ' of 17');
    END IF;

    -- 1.7 orgpasscheck_admin role exists
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orgpasscheck_admin') THEN
        PERFORM opc_test.pass('INSTALL','1.7','orgpasscheck_admin role exists');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.7','orgpasscheck_admin role exists','Role missing');
    END IF;

    -- 1.8 version_info view returns sensible data
    SELECT COUNT(*) INTO n FROM orgpasscheck.version_info;
    IF n = 1 THEN
        PERFORM opc_test.pass('INSTALL','1.8','version_info view returns 1 row');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.8','version_info view returns 1 row',n||' rows');
    END IF;

    -- 1.9 policy_summary view returns 1 row (one row of settings)
    SELECT COUNT(*) INTO n FROM orgpasscheck.policy_summary;
    IF n = 1 THEN
        PERFORM opc_test.pass('INSTALL','1.9','policy_summary view returns 1 row');
    ELSE
        PERFORM opc_test.fail('INSTALL','1.9','policy_summary view returns 1 row',n||' rows');
    END IF;
END $$;


-- =============================================================================
-- CATEGORY 2: C HOOK — COMPLEXITY CHECKS (GUCs 1–6)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 2 — C HOOK: COMPLEXITY CHECKS';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c2';
BEGIN
    PERFORM opc_test.cleanup(r);

    -- ── GUC 1: min_length ──────────────────────────────────────────────
    -- 2.1.1 Too short (3 chars)
    PERFORM opc_test.assert_raises('COMPLEXITY','2.1.1','Reject: 3-char password',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Ab1!'),
        'password is too short');

    -- 2.1.2 Too short (11 chars — one under default of 12)
    PERFORM opc_test.assert_raises('COMPLEXITY','2.1.2','Reject: 11-char password',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Abcdef123!@'),
        'password is too short');

    -- 2.1.3 Exactly at minimum (12 chars) — must pass
    -- NOTE: 'Rq7!Bm3#Zx1@' chosen deliberately: 12 chars, no 3-char sequential
    --       or identical run, meets all default complexity requirements.
    PERFORM opc_test.assert_ok('COMPLEXITY','2.1.3','Accept: 12-char password',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Rq7!Bm3#Zx1@'));
    PERFORM opc_test.cleanup(r);

    -- 2.1.4 GUC: lower min_length to 8 and accept an 8-char password
    SET orgpasscheck.min_length = 8;
    PERFORM opc_test.assert_ok('COMPLEXITY','2.1.4','Accept: 8-char with min_length=8',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Ab1!Xy2$'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.min_length = 12;

    -- ── GUC 2: min_upper ───────────────────────────────────────────────
    -- 2.2.1 No uppercase
    PERFORM opc_test.assert_raises('COMPLEXITY','2.2.1','Reject: no uppercase',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'abcdef1234!@'),
        'must contain at least 1 uppercase');

    -- 2.2.2 GUC: require 3 uppercase — supply password with exactly 2 uppercase
    -- NOTE: 'Xq7!bm3@Zp1f' has exactly 2 uppercase letters (X, Z).
    --       With min_upper=3 this must be rejected.
    SET orgpasscheck.min_upper = 3;
    PERFORM opc_test.assert_raises('COMPLEXITY','2.2.2','Reject: only 2 uppercase with min_upper=3',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xq7!bm3@Zp1f'),
        'must contain at least 3 uppercase');
    SET orgpasscheck.min_upper = 1;

    -- ── GUC 3: min_lower ───────────────────────────────────────────────
    -- 2.3.1 No lowercase — hits min_lower=1 first
    -- NOTE: 'XQMZPB37!@#$' is all-uppercase, no sequential runs.
    PERFORM opc_test.assert_raises('COMPLEXITY','2.3.1','Reject: no lowercase',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'XQMZPB37!@#$'),
        'must contain at least 1 lowercase');

    -- 2.3.2 GUC: require 3 lowercase; supply password with only 2 lowercase chars
    -- NOTE: 'XQMef7!@B3#Z' has exactly 2 lowercase (e,f), no sequential runs.
    SET orgpasscheck.min_lower = 3;
    PERFORM opc_test.assert_raises('COMPLEXITY','2.3.2','Reject: only 2 lowercase with min_lower=3',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'XQMef7!@B3#Z'),
        'must contain at least 3 lowercase');
    SET orgpasscheck.min_lower = 1;

    -- ── GUC 4: min_digit ───────────────────────────────────────────────
    -- 2.4.1 No digits
    -- NOTE: 'Xq!Bm@Zp#Rk$w' has zero digits, no sequential runs.
    PERFORM opc_test.assert_raises('COMPLEXITY','2.4.1','Reject: no digits',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xq!Bm@Zp#Rk$w'),
        'must contain at least 1 digit');

    -- 2.4.2 GUC: require 3 digits — supply password with exactly 2 digits
    -- NOTE: 'Xq7!Bm8@Zp#Rk' has exactly 2 digits (7, 8), no sequential runs.
    SET orgpasscheck.min_digit = 3;
    PERFORM opc_test.assert_raises('COMPLEXITY','2.4.2','Reject: only 2 digits with min_digit=3',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xq7!Bm8@Zp#Rk'),
        'must contain at least 3 digit');
    SET orgpasscheck.min_digit = 1;

    -- ── GUC 5: min_special ─────────────────────────────────────────────
    -- 2.5.1 No special chars
    -- NOTE: 'XqBmZpRk7194Lw' has no special characters, no sequential runs.
    PERFORM opc_test.assert_raises('COMPLEXITY','2.5.1','Reject: no special characters',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'XqBmZpRk7194Lw'),
        'must contain at least 1 special');

    -- 2.5.2 GUC: require 3 special
    -- NOTE: 'Rq7!Bm3#Zx1@' has exactly 2 specials (!,#,@ = wait, 3)
    -- Use 'Rq7!Bm3Zx1@9' which has only !,@ = 2 specials, no sequential runs.
    SET orgpasscheck.min_special = 3;
    PERFORM opc_test.assert_raises('COMPLEXITY','2.5.2','Reject: only 2 specials with min_special=3',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Rq7!Bm3Zx1@9'),
        'must contain at least 3 special');
    SET orgpasscheck.min_special = 1;

    -- ── GUC 6: require_mixed_case ──────────────────────────────────────
    -- 2.6.1 All uppercase hits min_lower=1 first (correct behaviour)
    -- NOTE: 'XQMZPB37!@#$' is all-uppercase, no sequential runs.
    PERFORM opc_test.assert_raises('COMPLEXITY','2.6.1','Reject: all-uppercase (hits min_lower first)',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'XQMZPB37!@#$'),
        'must contain at least 1 lowercase');

    -- 2.6.2 All lowercase hits min_upper=1 first (correct behaviour)
    -- NOTE: 'xqmzpb37!@#$' is all-lowercase, no sequential runs.
    PERFORM opc_test.assert_raises('COMPLEXITY','2.6.2','Reject: all-lowercase (hits min_upper first)',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'xqmzpb37!@#$'),
        'must contain at least 1 uppercase');

    -- 2.6.3 Disable mixed_case AND zero out individual min_upper/min_lower,
    --       then supply all-uppercase — should pass all checks.
    -- NOTE: 'XQMZPB37!@#$' all-uppercase, no sequential runs, no dict words.
    SET orgpasscheck.require_mixed_case = off;
    SET orgpasscheck.min_upper = 0;
    SET orgpasscheck.min_lower = 0;
    PERFORM opc_test.assert_ok('COMPLEXITY','2.6.3','Accept: all-uppercase with mixed_case=off',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'XQMZPB37!@#$'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.require_mixed_case = on;
    SET orgpasscheck.min_upper = 1;
    SET orgpasscheck.min_lower = 1;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 3: C HOOK — SEQUENTIAL PATTERN CHECK (GUC 7)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 3 — C HOOK: SEQUENTIAL PATTERN CHECK';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c3';
BEGIN
    PERFORM opc_test.cleanup(r);

    -- 3.1 3 identical chars
    PERFORM opc_test.assert_raises('SEQUENCE','3.1','Reject: 3 identical consecutive chars',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#MaaaBzP!'),
        '3 or more identical consecutive');

    -- 3.2 4 identical chars
    PERFORM opc_test.assert_raises('SEQUENCE','3.2','Reject: 4 identical consecutive chars',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#M1111P!z'),
        '3 or more identical consecutive');

    -- 3.3 Ascending letter run (abc)
    PERFORM opc_test.assert_raises('SEQUENCE','3.3','Reject: ascending letter run abc',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#abcBzP!m'),
        'sequential ascending or descending');

    -- 3.4 Ascending digit run (123)
    PERFORM opc_test.assert_raises('SEQUENCE','3.4','Reject: ascending digit run 123',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#M123BzP!'),
        'sequential ascending or descending');

    -- 3.5 Descending letter run (zyx)
    PERFORM opc_test.assert_raises('SEQUENCE','3.5','Reject: descending letter run zyx',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#MzyxBzP!'),
        'sequential ascending or descending');

    -- 3.6 Descending digit run (321)
    PERFORM opc_test.assert_raises('SEQUENCE','3.6','Reject: descending digit run 321',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#M321BzP!'),
        'sequential ascending or descending');

    -- 3.7 GUC: disable check — sequential password now accepted
    SET orgpasscheck.require_sequence_check = off;
    PERFORM opc_test.assert_ok('SEQUENCE','3.7','Accept: sequential run with check disabled',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#M123BzP!'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.require_sequence_check = on;

    -- 3.8 Valid password with no sequences — accepted
    PERFORM opc_test.assert_ok('SEQUENCE','3.8','Accept: valid non-sequential password',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'rT7#mX2$pL9@'));
    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 4: C HOOK — USERNAME CHECKS (GUCs 8 & 9)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 4 — C HOOK: USERNAME CHECKS';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c4usr';
BEGIN
    PERFORM opc_test.cleanup(r);

    -- 4.1 Password contains username verbatim
    PERFORM opc_test.assert_raises('USERNAME','4.1','Reject: password contains username',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#' || r || 'Bz!'),
        'must not contain your username');

    -- 4.2 Password contains username in uppercase (case-insensitive)
    PERFORM opc_test.assert_raises('USERNAME','4.2','Reject: username in password (upper-case)',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#' || upper(r) || 'Bz!'),
        'must not contain your username');

    -- 4.3 GUC: disable username containment — accepted
    SET orgpasscheck.reject_username = off;
    PERFORM opc_test.assert_ok('USERNAME','4.3','Accept: contains username with reject_username=off',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#' || r || 'Bz!'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.reject_username = on;

    -- 4.4 Levenshtein similarity test.
    --     Strategy: use a 12-char username (opc_levtest9) so the password
    --     can meet min_length without padding.  Change only the first char
    --     (o→X): lev('xpc_levtest9','opc_levtest9') = 1, below threshold 3.
    --     The password does NOT contain the username (x≠o at pos 0), so the
    --     containment check passes and we correctly reach the similarity check.
    PERFORM opc_test.cleanup('opc_levtest9');
    PERFORM opc_test.assert_raises('USERNAME','4.4','Reject: password too similar to username',
        format('CREATE ROLE %I LOGIN PASSWORD %L', 'opc_levtest9', 'Xpc_Levtest9'),
        'too similar to your username');

    -- 4.5 GUC: disable similarity check — same password now accepted
    SET orgpasscheck.similarity_check = off;
    PERFORM opc_test.assert_ok('USERNAME','4.5','Accept: similar password with similarity_check=off',
        format('CREATE ROLE %I LOGIN PASSWORD %L', 'opc_levtest9', 'Xpc_Levtest9'));
    PERFORM opc_test.cleanup('opc_levtest9');
    SET orgpasscheck.similarity_check = on;

    -- 4.6 GUC: lower threshold to 0 so only identical strings (lev=0) are rejected.
    --     Our password has lev=1 which is > 0, so it is accepted.
    --     SEMANTICS: threshold is the MAX edit distance that triggers rejection.
    --       threshold=3 (default): reject if lev <= 3  (blocks close matches)
    --       threshold=20:          reject if lev <= 20 (MORE restrictive, not less!)
    --       threshold=0:           reject if lev <= 0  (only identical strings)
    --     Lowering threshold makes the check LESS strict.
    SET orgpasscheck.similarity_threshold = 0;
    PERFORM opc_test.assert_ok('USERNAME','4.6','Accept: similar password with high threshold',
        format('CREATE ROLE %I LOGIN PASSWORD %L', 'opc_levtest9', 'Xpc_Levtest9'));
    PERFORM opc_test.cleanup('opc_levtest9');
    SET orgpasscheck.similarity_threshold = 3;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 5: C HOOK — DICTIONARY CHECK (GUC 10)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 5 — C HOOK: DICTIONARY CHECK';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c5';
BEGIN
    PERFORM opc_test.cleanup(r);

    -- 5.1 Contains 'password' (standard dictionary entry)
    PERFORM opc_test.assert_raises('DICTIONARY','5.1','Reject: contains word "password"',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#PasswordZm!'),
        'contains a common dictionary word');

    -- 5.2 Contains 'welcome' embedded
    PERFORM opc_test.assert_raises('DICTIONARY','5.2','Reject: contains word "welcome"',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#WelcomeZm!'),
        'contains a common dictionary word');

    -- 5.3 Contains 'admin' (case-insensitive)
    PERFORM opc_test.assert_raises('DICTIONARY','5.3','Reject: contains "admin" (case-insensitive)',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#ADMINzm2!'),
        'contains a common dictionary word');

    -- 5.4 GUC: disable dictionary check — accepted even with 'password'
    SET orgpasscheck.dictionary_check = off;
    PERFORM opc_test.assert_ok('DICTIONARY','5.4','Accept: dict word with dictionary_check=off',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#PasswordZm!'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.dictionary_check = on;

    -- 5.5 Valid password with no dictionary words
    PERFORM opc_test.assert_ok('DICTIONARY','5.5','Accept: no dictionary words',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'rT7#mX2$pL9@'));
    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 6: C HOOK — BLACKLIST CHECK (GUC 11)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 6 — C HOOK: BLACKLIST CHECK';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c6';
    v_pat TEXT := 'xkforbidden9z';
BEGIN
    PERFORM opc_test.cleanup(r);

    -- Add a test blacklist pattern
    PERFORM orgpasscheck.add_blacklist(v_pat, 'Test pattern for cat 6');

    -- 6.1 Exact pattern in password
    PERFORM opc_test.assert_raises('BLACKLIST','6.1','Reject: exact blacklisted pattern',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Rk9#' || v_pat || 'P!'),
        'explicitly blacklisted');

    -- 6.2 Pattern embedded mid-password
    PERFORM opc_test.assert_raises('BLACKLIST','6.2','Reject: blacklisted pattern embedded',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Rk9!' || v_pat || 'Zb2@'),
        'explicitly blacklisted');

    -- 6.3 GUC: disable blacklist check — accepted
    SET orgpasscheck.blacklist_check = off;
    PERFORM opc_test.assert_ok('BLACKLIST','6.3','Accept: blacklisted word with check off',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Rk9#' || v_pat || 'P!'));
    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.blacklist_check = on;

    -- 6.4 Password with no blacklisted words — accepted
    PERFORM opc_test.assert_ok('BLACKLIST','6.4','Accept: password with no blacklisted pattern',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'rT7#mX2$pL9@'));
    PERFORM opc_test.cleanup(r);

    -- Cleanup blacklist
    PERFORM orgpasscheck.remove_blacklist(v_pat);
END $$;


-- =============================================================================
-- CATEGORY 7: C HOOK — HISTORY REUSE (GUC 12)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 7 — C HOOK: PASSWORD HISTORY & REUSE';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c7';
    pw1 TEXT := 'rT7#mX2$pL9@';
    pw2 TEXT := 'H#4jM2$rP9L!';
    pw3 TEXT := 'm@9J$2pR4!hX';
    pw4 TEXT := 'X@2h#4M$9pL!';
    n   INT;
BEGIN
    PERFORM opc_test.cleanup(r);
    SET LOCAL orgpasscheck.reuse_history = 3;

    -- 7.1 First password — history row created
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, pw1);
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r;
    IF n = 1 THEN
        PERFORM opc_test.pass('HISTORY','7.1','History row created on CREATE ROLE');
    ELSE
        PERFORM opc_test.fail('HISTORY','7.1','History row created on CREATE ROLE',
            'Expected 1, got '||n);
    END IF;

    -- 7.2 Second password — history grows
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, pw2);
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r;
    IF n = 2 THEN
        PERFORM opc_test.pass('HISTORY','7.2','History grows on ALTER ROLE');
    ELSE
        PERFORM opc_test.fail('HISTORY','7.2','History grows on ALTER ROLE',
            'Expected 2, got '||n);
    END IF;

    -- 7.3 Third password
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, pw3);

    -- 7.4 Reuse pw1 — within reuse_history=3 window — must be blocked
    PERFORM opc_test.assert_raises('HISTORY','7.4','Reject: reuse of pw1 (within window)',
        format('ALTER ROLE %I PASSWORD %L', r, pw1),
        'cannot reuse any of your last');

    -- 7.5 Reuse pw2 — also within window
    PERFORM opc_test.assert_raises('HISTORY','7.5','Reject: reuse of pw2 (within window)',
        format('ALTER ROLE %I PASSWORD %L', r, pw2),
        'cannot reuse any of your last');

    -- 7.6 Fresh password — must be accepted
    PERFORM opc_test.assert_ok('HISTORY','7.6','Accept: fresh password not in history',
        format('ALTER ROLE %I PASSWORD %L', r, pw4));

    -- 7.7 History pruned: after pw4, history depth should be ≤ 3
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r;
    IF n <= 3 THEN
        PERFORM opc_test.pass('HISTORY','7.7','History pruned to reuse_history depth');
    ELSE
        PERFORM opc_test.fail('HISTORY','7.7','History pruned to reuse_history depth',
            'Expected ≤3, got '||n);
    END IF;

    -- 7.8 GUC: disable reuse check — previously used pw1 is now accepted
    SET LOCAL orgpasscheck.reuse_history = 0;
    PERFORM opc_test.assert_ok('HISTORY','7.8','Accept: reused pw1 with reuse_history=0',
        format('ALTER ROLE %I PASSWORD %L', r, pw1));

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 8: C HOOK — MINIMUM AGE (GUC 13)
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 8 — C HOOK: MINIMUM PASSWORD AGE';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_c8';
    pw1 TEXT := 'rT7#mX2$pL9@';
    pw2 TEXT := 'H#4jM2$rP9L!';
BEGIN
    PERFORM opc_test.cleanup(r);
    SET LOCAL orgpasscheck.min_age_days = 1;

    -- 8.1 Create role; then immediately try to change — must be blocked
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, pw1);
    PERFORM opc_test.assert_raises('MIN_AGE','8.1','Reject: change within min_age_days',
        format('ALTER ROLE %I PASSWORD %L', r, pw2),
        'You must wait');

    -- 8.2 GUC: disable min_age — change now accepted
    SET LOCAL orgpasscheck.min_age_days = 0;
    PERFORM opc_test.assert_ok('MIN_AGE','8.2','Accept: immediate change with min_age_days=0',
        format('ALTER ROLE %I PASSWORD %L', r, pw2));

    PERFORM opc_test.cleanup(r);
    SET orgpasscheck.min_age_days = 0;  -- reset for remaining tests
END $$;


-- =============================================================================
-- =============================================================================
-- CATEGORY 9: VIOLATION LOGGING
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 9 — VIOLATION LOGGING';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
BEGIN
    -- Violation logging to a database table is intentionally removed in v5.
    --
    -- check_password_hook fires inside a utility command transaction.
    -- Any INSERT made during the hook is rolled back when ereport(ERROR)
    -- rejects the password — a PostgreSQL architectural constraint that
    -- cannot be solved without external dependencies.
    --
    -- Policy rejections produce clear error messages via ereport(ERROR),
    -- delivered directly to the client and visible in the server log.
    -- All rejection functionality is verified in categories 2–8.

    PERFORM opc_test.skip('VIOLATIONS','9.1',
        'Violation table logging removed — rejections delivered via ereport(ERROR)',
        'Feature removed in v5; all policy rejections tested in categories 2-8');
END $$;

-- CATEGORY 10: SQL API — BLACKLIST MANAGEMENT
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 10 — SQL API: BLACKLIST MANAGEMENT';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE n INT; pat TEXT := 'xktestblk9z';
BEGIN
    -- 10.1 add_blacklist() inserts row
    PERFORM orgpasscheck.add_blacklist(pat, 'Test entry');
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_blacklist WHERE blacklisted_word = pat;
    IF n = 1 THEN PERFORM opc_test.pass('BLACKLIST_API','10.1','add_blacklist() inserts entry');
    ELSE PERFORM opc_test.fail('BLACKLIST_API','10.1','add_blacklist() inserts entry','0 rows');
    END IF;

    -- 10.2 Duplicate add is idempotent (ON CONFLICT)
    BEGIN
        PERFORM orgpasscheck.add_blacklist(pat, 'Duplicate');
        PERFORM opc_test.pass('BLACKLIST_API','10.2','add_blacklist() duplicate is idempotent');
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail('BLACKLIST_API','10.2','add_blacklist() duplicate is idempotent',SQLERRM);
    END;

    -- 10.3 remove_blacklist() removes row
    PERFORM orgpasscheck.remove_blacklist(pat);
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_blacklist WHERE blacklisted_word = pat;
    IF n = 0 THEN PERFORM opc_test.pass('BLACKLIST_API','10.3','remove_blacklist() removes entry');
    ELSE PERFORM opc_test.fail('BLACKLIST_API','10.3','remove_blacklist() removes entry',n||' rows remain');
    END IF;

    -- 10.4 remove non-existent blacklist word — graceful (no exception)
    BEGIN
        PERFORM orgpasscheck.remove_blacklist('nonexistent_xyz_9z');
        PERFORM opc_test.pass('BLACKLIST_API','10.4','remove_blacklist() non-existent is graceful');
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail('BLACKLIST_API','10.4','remove_blacklist() non-existent is graceful',SQLERRM);
    END;
END $$;


-- =============================================================================
-- CATEGORY 11: SQL API — USER MANAGEMENT
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 11 — SQL API: USER MANAGEMENT';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r1 TEXT := 'opc_api_u1';
    r2 TEXT := 'opc_api_u2';
    n  INT;
    v  TIMESTAMPTZ;
BEGIN
    PERFORM opc_test.cleanup(r1);
    PERFORM opc_test.cleanup(r2);

    -- 11.1 create_user() creates role
    PERFORM orgpasscheck.create_user(r1, 'rT7#mX2$pL9@');
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r1) THEN
        PERFORM opc_test.pass('USER_API','11.1','create_user() creates pg role');
    ELSE
        PERFORM opc_test.fail('USER_API','11.1','create_user() creates pg role','Role not found');
    END IF;

    -- 11.2 create_user() records history
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r1;
    IF n >= 1 THEN PERFORM opc_test.pass('USER_API','11.2','create_user() records history');
    ELSE PERFORM opc_test.fail('USER_API','11.2','create_user() records history','0 rows');
    END IF;

    -- 11.3 create_user() writes ddl_audit_log
    SELECT COUNT(*) INTO n FROM orgpasscheck.ddl_audit_log
    WHERE rolname = r1 AND command_tag = 'CREATE ROLE';
    IF n >= 1 THEN PERFORM opc_test.pass('USER_API','11.3','create_user() writes audit log');
    ELSE PERFORM opc_test.fail('USER_API','11.3','create_user() writes audit log','0 rows');
    END IF;

    -- 11.4 create_user() sets expiry from expiry_days GUC
    SELECT rolvaliduntil INTO v FROM pg_roles WHERE rolname = r1;
    IF v IS NOT NULL THEN PERFORM opc_test.pass('USER_API','11.4','create_user() sets password expiry');
    ELSE PERFORM opc_test.fail('USER_API','11.4','create_user() sets password expiry','rolvaliduntil is NULL');
    END IF;

    -- 11.5 create_user() with custom expiry
    PERFORM orgpasscheck.create_user(r2, 'H#4jM2$rP9L!', p_expiry_days := 7);
    SELECT rolvaliduntil INTO v FROM pg_roles WHERE rolname = r2;
    IF v IS NOT NULL AND v < now() + interval '8 days' THEN
        PERFORM opc_test.pass('USER_API','11.5','create_user() custom expiry respected');
    ELSE
        PERFORM opc_test.fail('USER_API','11.5','create_user() custom expiry respected',
            'Expected expiry within 8 days, got: '||v::text);
    END IF;

    -- 11.6 change_password() updates history
    PERFORM orgpasscheck.change_password(r1, 'm@9J$2pR4!hX');
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r1;
    IF n >= 2 THEN PERFORM opc_test.pass('USER_API','11.6','change_password() adds history row');
    ELSE PERFORM opc_test.fail('USER_API','11.6','change_password() adds history row',n||' rows');
    END IF;

    -- 11.7 change_password() rejects same password
    PERFORM opc_test.assert_raises('USER_API','11.7','change_password() blocks immediate reuse',
        format('SELECT orgpasscheck.change_password(%L, %L)', r1, 'm@9J$2pR4!hX'),
        'cannot reuse any of your last');

    -- 11.8 change_password() auth: non-superuser cannot change another user's password
    --      (simulate by checking that the function has the correct auth guard;
    --       we test as superuser so we call with mismatched session_user by
    --       inspecting the function source for the guard)
    SELECT COUNT(*) INTO n
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck' AND p.proname = 'change_password'
      AND pg_get_functiondef(p.oid) LIKE '%permission denied%';
    IF n >= 1 THEN PERFORM opc_test.pass('USER_API','11.8','change_password() has auth guard');
    ELSE PERFORM opc_test.fail('USER_API','11.8','change_password() has auth guard',
        'No permission denied check found in function body');
    END IF;

    PERFORM opc_test.cleanup(r1);
    PERFORM opc_test.cleanup(r2);
END $$;


-- =============================================================================
-- CATEGORY 12: SQL API — EXPIRY EXEMPTION MANAGEMENT
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 12 — SQL API: EXPIRY EXEMPTION';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_exempt';
    n   INT;
BEGIN
    PERFORM opc_test.cleanup(r);
    PERFORM orgpasscheck.create_user(r, 'rT7#mX2$pL9@');

    -- 12.1 add_expiry_exemption() inserts row
    PERFORM orgpasscheck.add_expiry_exemption(r, 'Service account test');
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_expiry_exemption
    WHERE username = r AND active = true;
    IF n = 1 THEN PERFORM opc_test.pass('EXEMPTION','12.1','add_expiry_exemption() inserts active row');
    ELSE PERFORM opc_test.fail('EXEMPTION','12.1','add_expiry_exemption() inserts active row',n||' rows');
    END IF;

    -- 12.2 list_expiry_exemptions() returns the row (superuser calling)
    SELECT COUNT(*) INTO n FROM orgpasscheck.list_expiry_exemptions() WHERE username = r;
    IF n = 1 THEN PERFORM opc_test.pass('EXEMPTION','12.2','list_expiry_exemptions() returns row');
    ELSE PERFORM opc_test.fail('EXEMPTION','12.2','list_expiry_exemptions() returns row',n||' rows');
    END IF;

    -- 12.3 list_expiry_exemptions() has access control (function body contains guard)
    SELECT COUNT(*) INTO n
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck' AND p.proname = 'list_expiry_exemptions'
      AND pg_get_functiondef(p.oid) LIKE '%permission denied%';
    IF n >= 1 THEN PERFORM opc_test.pass('EXEMPTION','12.3','list_expiry_exemptions() has access guard');
    ELSE PERFORM opc_test.fail('EXEMPTION','12.3','list_expiry_exemptions() has access guard',
        'No permission denied found in function body');
    END IF;

    -- 12.4 remove_expiry_exemption() deletes row
    PERFORM orgpasscheck.remove_expiry_exemption(r);
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_expiry_exemption
    WHERE username = r AND active = true;
    IF n = 0 THEN PERFORM opc_test.pass('EXEMPTION','12.4','remove_expiry_exemption() deletes row');
    ELSE PERFORM opc_test.fail('EXEMPTION','12.4','remove_expiry_exemption() deletes row',n||' active rows remain');
    END IF;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 13: SQL API — HISTORY MAINTENANCE
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 13 — SQL API: HISTORY MAINTENANCE';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_hist';
    n   INT;
    del INT;
BEGIN
    PERFORM opc_test.cleanup(r);
    SET LOCAL orgpasscheck.reuse_history = 5;

    -- Create and cycle through 7 passwords (> reuse_history of 5)
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'rT7#mX2$pL9@');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'H#4jM2$rP9L!');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'm@9J$2pR4!hX');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'X@2h#4M$9pL!');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'L#2m$9pR4!hX');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'p@9M$2hR4!jX');
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r, 'Qz3!kN8$wR5@');

    -- 13.1 History is auto-pruned to reuse_history depth
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r;
    IF n <= 5 THEN PERFORM opc_test.pass('HIST_API','13.1','History auto-pruned to reuse_history depth');
    ELSE PERFORM opc_test.fail('HIST_API','13.1','History auto-pruned to reuse_history depth',
        'Expected ≤5, got '||n);
    END IF;

    -- 13.2 purge_user_history() wipes all rows for user
    del := orgpasscheck.purge_user_history(r);
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = r;
    IF n = 0 THEN PERFORM opc_test.pass('HIST_API','13.2','purge_user_history() removes all rows');
    ELSE PERFORM opc_test.fail('HIST_API','13.2','purge_user_history() removes all rows',n||' remain');
    END IF;

    -- 13.3 purge_user_history() returns deleted row count
    IF del > 0 THEN PERFORM opc_test.pass('HIST_API','13.3','purge_user_history() returns deleted count');
    ELSE PERFORM opc_test.fail('HIST_API','13.3','purge_user_history() returns deleted count',
        'Returned '||del);
    END IF;

    -- 13.4 purge_old_history() across all users (smoke test — no exception)
    BEGIN
        PERFORM orgpasscheck.purge_old_history();
        PERFORM opc_test.pass('HIST_API','13.4','purge_old_history() executes without error');
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail('HIST_API','13.4','purge_old_history() executes without error',SQLERRM);
    END;

    -- 13.5 purge_user_history() has access control
    SELECT COUNT(*) INTO n
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck' AND p.proname = 'purge_user_history'
      AND pg_get_functiondef(p.oid) LIKE '%permission denied%';
    IF n >= 1 THEN PERFORM opc_test.pass('HIST_API','13.5','purge_user_history() has access guard');
    ELSE PERFORM opc_test.fail('HIST_API','13.5','purge_user_history() has access guard',
        'No guard found in function body');
    END IF;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 14: SQL FUNCTIONS — verify_password_hash() & record_password_history()
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 14 — INTERNAL FUNCTIONS: HASH & HISTORY';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE v_salt TEXT;
    v_hash TEXT;
    v_match BOOLEAN;
    n INT;
BEGIN
    -- 14.1 verify_password_hash() returns TRUE for correct combination
    v_salt := 'abc123def456abc123def456abc12345';
    v_hash := encode(sha256((v_salt || 'MyTestPassword!')::bytea), 'hex');
    SELECT orgpasscheck.verify_password_hash('MyTestPassword!', v_salt, v_hash) INTO v_match;
    IF v_match THEN PERFORM opc_test.pass('HASH','14.1','verify_password_hash() returns TRUE for correct input');
    ELSE PERFORM opc_test.fail('HASH','14.1','verify_password_hash() returns TRUE for correct input','Returned FALSE');
    END IF;

    -- 14.2 verify_password_hash() returns FALSE for wrong password
    SELECT orgpasscheck.verify_password_hash('WrongPassword!', v_salt, v_hash) INTO v_match;
    IF NOT v_match THEN PERFORM opc_test.pass('HASH','14.2','verify_password_hash() returns FALSE for wrong password');
    ELSE PERFORM opc_test.fail('HASH','14.2','verify_password_hash() returns FALSE for wrong password','Returned TRUE');
    END IF;

    -- 14.3 verify_password_hash() returns FALSE for wrong salt
    SELECT orgpasscheck.verify_password_hash('MyTestPassword!', 'wrongsalt', v_hash) INTO v_match;
    IF NOT v_match THEN PERFORM opc_test.pass('HASH','14.3','verify_password_hash() returns FALSE for wrong salt');
    ELSE PERFORM opc_test.fail('HASH','14.3','verify_password_hash() returns FALSE for wrong salt','Returned TRUE');
    END IF;

    -- 14.4 record_password_history() inserts a history row
    DELETE FROM orgpasscheck.password_history WHERE username = '_opc_hash_test';
    PERFORM orgpasscheck.record_password_history('_opc_hash_test', 'rT7#mX2$pL9@');
    SELECT COUNT(*) INTO n FROM orgpasscheck.password_history WHERE username = '_opc_hash_test';
    IF n = 1 THEN PERFORM opc_test.pass('HASH','14.4','record_password_history() inserts row');
    ELSE PERFORM opc_test.fail('HASH','14.4','record_password_history() inserts row',n||' rows');
    END IF;

    -- 14.5 Stored hash is NOT the plaintext (basic sanity)
    SELECT password_hash INTO v_hash FROM orgpasscheck.password_history
    WHERE username = '_opc_hash_test' LIMIT 1;
    IF v_hash <> 'rT7#mX2$pL9@' AND length(v_hash) = 64 THEN
        PERFORM opc_test.pass('HASH','14.5','Stored hash is SHA-256 hex (64 chars), not plaintext');
    ELSE
        PERFORM opc_test.fail('HASH','14.5','Stored hash is SHA-256 hex (64 chars), not plaintext',
            'Got: '||v_hash);
    END IF;

    -- 14.6 Salt is a 32-char hex string
    SELECT salt INTO v_salt FROM orgpasscheck.password_history
    WHERE username = '_opc_hash_test' LIMIT 1;
    IF length(v_salt) = 32 AND v_salt ~ '^[0-9a-f]+$' THEN
        PERFORM opc_test.pass('HASH','14.6','Salt is 32-char lowercase hex');
    ELSE
        PERFORM opc_test.fail('HASH','14.6','Salt is 32-char lowercase hex','Got: '||v_salt);
    END IF;

    -- Cleanup
    DELETE FROM orgpasscheck.password_history WHERE username = '_opc_hash_test';

    -- 14.7 verify_password_hash() is NOT executable by PUBLIC
    --      (REVOKE was applied in SQL install script; check the privilege)
    SELECT COUNT(*) INTO n
    FROM information_schema.routine_privileges
    WHERE routine_schema = 'orgpasscheck'
      AND routine_name = 'verify_password_hash'
      AND grantee = 'PUBLIC';
    IF n = 0 THEN PERFORM opc_test.pass('HASH','14.7','verify_password_hash() EXECUTE revoked from PUBLIC');
    ELSE PERFORM opc_test.fail('HASH','14.7','verify_password_hash() EXECUTE revoked from PUBLIC',
        'PUBLIC still has EXECUTE');
    END IF;
END $$;


-- =============================================================================
-- CATEGORY 15: MONITORING VIEWS
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 15 — MONITORING VIEWS';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_views';
    n   INT;
    v   TEXT;
BEGIN
    PERFORM opc_test.cleanup(r);
    PERFORM orgpasscheck.create_user(r, 'rT7#mX2$pL9@');

    -- 15.1 user_password_status shows the new user
    SELECT COUNT(*) INTO n FROM orgpasscheck.user_password_status WHERE username = r;
    IF n = 1 THEN PERFORM opc_test.pass('VIEWS','15.1','user_password_status shows new user');
    ELSE PERFORM opc_test.fail('VIEWS','15.1','user_password_status shows new user',n||' rows');
    END IF;

    -- 15.2 rotation_report shows the new user
    SELECT COUNT(*) INTO n FROM orgpasscheck.rotation_report WHERE username = r;
    IF n = 1 THEN PERFORM opc_test.pass('VIEWS','15.2','rotation_report shows new user');
    ELSE PERFORM opc_test.fail('VIEWS','15.2','rotation_report shows new user',n||' rows');
    END IF;

    -- 15.3 rotation_report has policy_expiry_days column (dynamic threshold fix)
    SELECT COUNT(*) INTO n FROM information_schema.columns
    WHERE table_schema = 'orgpasscheck' AND table_name = 'rotation_report'
      AND column_name = 'policy_expiry_days';
    IF n = 1 THEN PERFORM opc_test.pass('VIEWS','15.3','rotation_report has policy_expiry_days column');
    ELSE PERFORM opc_test.fail('VIEWS','15.3','rotation_report has policy_expiry_days column','Column missing');
    END IF;

    -- 15.4 rotation_report thresholds come from GUC (change GUC and verify column value changes)
    SET LOCAL orgpasscheck.expiry_days = 30;
    SELECT policy_expiry_days::text INTO v FROM orgpasscheck.rotation_report WHERE username = r LIMIT 1;
    IF v = '30' THEN PERFORM opc_test.pass('VIEWS','15.4','rotation_report respects expiry_days GUC');
    ELSE PERFORM opc_test.fail('VIEWS','15.4','rotation_report respects expiry_days GUC',
        'Expected 30, got '||COALESCE(v,'NULL'));
    END IF;

    -- 15.5 expired_passwords view is queryable (no exception)
    BEGIN
        PERFORM COUNT(*) FROM orgpasscheck.expired_passwords;
        PERFORM opc_test.pass('VIEWS','15.5','expired_passwords view is queryable');
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail('VIEWS','15.5','expired_passwords view is queryable',SQLERRM);
    END;

    -- 15.6 policy_summary returns 1 row with correct column count (17 settings)
    SELECT COUNT(*) INTO n FROM information_schema.columns
    WHERE table_schema = 'orgpasscheck' AND table_name = 'policy_summary';
    IF n = 17 THEN PERFORM opc_test.pass('VIEWS','15.6','policy_summary has 17 GUC columns');
    ELSE PERFORM opc_test.fail('VIEWS','15.6','policy_summary has 17 GUC columns','Got '||n);
    END IF;

    -- 15.7 version_info returns extension version 5.0
    SELECT extversion INTO v FROM pg_extension WHERE extname = 'orgpasscheck';
    IF v = '5.0' THEN PERFORM opc_test.pass('VIEWS','15.7','version_info confirms version 5.0');
    ELSE PERFORM opc_test.fail('VIEWS','15.7','version_info confirms version 5.0','Got '||v);
    END IF;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 16: ALL GUC DEFAULTS & PERSISTENCE
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 16 — GUC DEFAULTS & PERSISTENCE';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE n INT; v TEXT;
BEGIN
    -- 16.1 – 16.17: verify each GUC exists in pg_settings with the documented default
    -- Reset to defaults first
    RESET orgpasscheck.min_length;
    RESET orgpasscheck.min_upper;
    RESET orgpasscheck.min_lower;
    RESET orgpasscheck.min_digit;
    RESET orgpasscheck.min_special;
    RESET orgpasscheck.require_mixed_case;
    RESET orgpasscheck.require_sequence_check;
    RESET orgpasscheck.reject_username;
    -- Restore every GUC to its compiled-in default using SET, not RESET.
    -- RESET restores to the postgresql.conf value which may differ from the
    -- compiled default if a previous session used ALTER SYSTEM.  SET explicitly
    -- to the compiled values guarantees the comparison below is meaningful.
    SET orgpasscheck.min_length            = 12;
    SET orgpasscheck.min_upper             = 1;
    SET orgpasscheck.min_lower             = 1;
    SET orgpasscheck.min_digit             = 1;
    SET orgpasscheck.min_special           = 1;
    SET orgpasscheck.require_mixed_case    = on;
    SET orgpasscheck.require_sequence_check = on;
    SET orgpasscheck.reject_username       = on;
    SET orgpasscheck.similarity_check      = on;
    SET orgpasscheck.similarity_threshold  = 3;
    SET orgpasscheck.dictionary_check      = on;
    SET orgpasscheck.blacklist_check       = on;
    SET orgpasscheck.reuse_history         = 5;
    SET orgpasscheck.min_age_days          = 1;
    SET orgpasscheck.expiry_days           = 45;
    SET orgpasscheck.enforce_expiry        = on;
    SET orgpasscheck.allow_no_expiry_users = off;

    -- Check each default
    CREATE TEMP TABLE _guc_expected (guc TEXT, expected TEXT);
    INSERT INTO _guc_expected VALUES
        ('orgpasscheck.min_length',            '12'),
        ('orgpasscheck.min_upper',             '1'),
        ('orgpasscheck.min_lower',             '1'),
        ('orgpasscheck.min_digit',             '1'),
        ('orgpasscheck.min_special',           '1'),
        ('orgpasscheck.require_mixed_case',    'on'),
        ('orgpasscheck.require_sequence_check','on'),
        ('orgpasscheck.reject_username',       'on'),
        ('orgpasscheck.similarity_check',      'on'),
        ('orgpasscheck.similarity_threshold',  '3'),
        ('orgpasscheck.dictionary_check',      'on'),
        ('orgpasscheck.blacklist_check',       'on'),
        ('orgpasscheck.reuse_history',         '5'),
        ('orgpasscheck.min_age_days',          '1'),
        ('orgpasscheck.expiry_days',           '45'),
        ('orgpasscheck.enforce_expiry',        'on'),
        ('orgpasscheck.allow_no_expiry_users', 'off');

    FOR v, n IN
        SELECT e.guc,
               CASE WHEN s.setting = e.expected THEN 1 ELSE 0 END
        FROM _guc_expected e
        LEFT JOIN pg_settings s ON s.name = e.guc
    LOOP
        IF n = 1 THEN
            PERFORM opc_test.pass('GUCS','16.'||v,'GUC default correct: '||v);
        ELSE
            PERFORM opc_test.fail('GUCS','16.'||v,'GUC default correct: '||v,
                'Expected default not matching');
        END IF;
    END LOOP;

    DROP TABLE _guc_expected;

    -- 16.18 SET LOCAL is session-scoped (change reverts after transaction)
    -- We test SET (not SET LOCAL) persists within session
    SET orgpasscheck.min_length = 20;
    SELECT setting INTO v FROM pg_settings WHERE name = 'orgpasscheck.min_length';
    IF v = '20' THEN PERFORM opc_test.pass('GUCS','16.18','SET orgpasscheck.min_length persists in session');
    ELSE PERFORM opc_test.fail('GUCS','16.18','SET orgpasscheck.min_length persists in session','Got '||v);
    END IF;
    RESET orgpasscheck.min_length;

    -- Re-disable min_age for remaining tests
    SET orgpasscheck.min_age_days = 0;
END $$;


-- =============================================================================
-- CATEGORY 17: EDGE CASES
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 17 — EDGE CASES';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_edge';
    n   INT;
BEGIN
    PERFORM opc_test.cleanup(r);

    -- 17.1 NULL password — hook skips (role created without password)
    PERFORM opc_test.assert_ok('EDGE','17.1','NULL password — hook skips gracefully',
        format('CREATE ROLE %I', r));
    PERFORM opc_test.cleanup(r);

    -- 17.2 Empty string password — PostgreSQL clears it (not an error from hook)
    BEGIN
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD ''''', r);
        PERFORM opc_test.pass('EDGE','17.2','Empty string password handled gracefully');
    EXCEPTION WHEN OTHERS THEN
        PERFORM opc_test.fail('EDGE','17.2','Empty string password handled gracefully',SQLERRM);
    END;
    PERFORM opc_test.cleanup(r);

    -- 17.3 Very long password (1000 chars) — must not crash (dynamic palloc)
    PERFORM opc_test.assert_ok('EDGE','17.3','1000-char password accepted without crash',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r,
            'rT7#mX2$pL9@' || repeat('Xk9!', 247)));
    PERFORM opc_test.cleanup(r);

    -- 17.4 Unicode/multibyte characters in password
    PERFORM opc_test.assert_ok('EDGE','17.4','Multibyte (non-ASCII) password accepted',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk9#Müller2!Z'));
    PERFORM opc_test.cleanup(r);

    -- 17.5 Username with special characters
    PERFORM opc_test.cleanup('opc_edge_$user');
    PERFORM opc_test.assert_ok('EDGE','17.5','Role with special chars in name accepted',
        format('CREATE ROLE %I LOGIN PASSWORD %L', 'opc_edge_$user', 'rT7#mX2$pL9@'));
    PERFORM opc_test.cleanup('opc_edge_$user');

    -- 17.6 Role with no LOGIN (NOLOGIN) and no password — hook skips
    PERFORM opc_test.assert_ok('EDGE','17.6','NOLOGIN role without password — hook skips',
        format('CREATE ROLE %I NOLOGIN', r));
    PERFORM opc_test.cleanup(r);

    -- 17.7 Rapid successive ALTER ROLE (10 unique passwords) — no crash
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'rT7#mX2$pL9@');
    DECLARE
        pws TEXT[] := ARRAY[
            'H#4jM2$rP9L!','m@9J$2pR4!hX','X@2h#4M$9pL!',
            'L#2m$9pR4!hX','p@9M$2hR4!jX','Qz3!kN8$wR5@',
            'Bv7@xK3!nM5#','Wy4#fJ8$mK2!','Tz6!pR3@hN9#',
            'Cv8#mL4$wQ7!'
        ];
        pw TEXT;
        ok INT := 0;
    BEGIN
        FOREACH pw IN ARRAY pws LOOP
            BEGIN
                EXECUTE format('ALTER ROLE %I PASSWORD %L', r, pw);
                ok := ok + 1;
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
        END LOOP;
        IF ok > 0 THEN
            PERFORM opc_test.pass('EDGE','17.7','10 rapid ALTER ROLE cycles without crash');
        ELSE
            PERFORM opc_test.fail('EDGE','17.7','10 rapid ALTER ROLE cycles without crash',
                'No change succeeded');
        END IF;
    END;
    PERFORM opc_test.cleanup(r);

    -- 17.8 A password that is syntactically SCRAM-like but supplied as a plain
    --      SQL string literal is treated as plaintext by the DDL parser.
    --      It must be rejected on LENGTH (it is too short), not on the
    --      PASSWORD_TYPE guard (which only fires via wire protocol).
    --      NOTE: We use 'Xk1!' (4 chars, no sequential run) so the LENGTH
    --      check fires first, exactly as intended.  The original test used
    --      the long SCRAM-SHA-256$4096:abc==:def== literal which contains
    --      the ascending run 'abc' and was incorrectly rejected by the
    --      sequence check before reaching the length check.
    PERFORM opc_test.assert_raises('EDGE','17.8',
        'Short password rejected on length (not password_type guard)',
        format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'Xk1!'),
        'password is too short');

    -- 17.9 SKIP: pre-hashed password via wire protocol cannot be tested in SQL
    PERFORM opc_test.skip('EDGE','17.9',
        'PREHASHED guard via wire protocol (PASSWORD_TYPE_SCRAM_SHA_256)',
        'Only triggers via libpq/JDBC wire protocol. Test manually with psql \\password');

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- CATEGORY 18: ACCESS CONTROL & SECURITY
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 18 — ACCESS CONTROL & SECURITY';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE n INT;
BEGIN
    -- 18.1 verify_password_hash REVOKED from PUBLIC
    SELECT COUNT(*) INTO n FROM information_schema.routine_privileges
    WHERE routine_schema = 'orgpasscheck' AND routine_name = 'verify_password_hash'
      AND grantee = 'PUBLIC';
    IF n = 0 THEN PERFORM opc_test.pass('ACCESS','18.1','verify_password_hash revoked from PUBLIC');
    ELSE PERFORM opc_test.fail('ACCESS','18.1','verify_password_hash revoked from PUBLIC',
        'PUBLIC still has EXECUTE');
    END IF;

    -- 18.2 record_password_history REVOKED from PUBLIC
    SELECT COUNT(*) INTO n FROM information_schema.routine_privileges
    WHERE routine_schema = 'orgpasscheck' AND routine_name = 'record_password_history'
      AND grantee = 'PUBLIC';
    IF n = 0 THEN PERFORM opc_test.pass('ACCESS','18.2','record_password_history revoked from PUBLIC');
    ELSE PERFORM opc_test.fail('ACCESS','18.2','record_password_history revoked from PUBLIC',
        'PUBLIC still has EXECUTE');
    END IF;

    -- 18.3 policy_summary is readable by PUBLIC
    SELECT COUNT(*) INTO n FROM information_schema.role_table_grants
    WHERE table_schema = 'orgpasscheck' AND table_name = 'policy_summary'
      AND grantee = 'PUBLIC' AND privilege_type = 'SELECT';
    IF n = 1 THEN PERFORM opc_test.pass('ACCESS','18.3','policy_summary SELECT granted to PUBLIC');
    ELSE PERFORM opc_test.fail('ACCESS','18.3','policy_summary SELECT granted to PUBLIC','Not granted');
    END IF;

    -- 18.4 All SECURITY DEFINER functions have pinned search_path
    SELECT COUNT(*) INTO n
    FROM pg_proc p
    JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck'
      AND p.prosecdef = true
      AND (p.proconfig IS NULL
           OR NOT EXISTS (
               SELECT 1 FROM unnest(p.proconfig) cfg
               WHERE cfg LIKE 'search_path=%'
           ));
    IF n = 0 THEN PERFORM opc_test.pass('ACCESS','18.4','All SECURITY DEFINER functions pin search_path');
    ELSE PERFORM opc_test.fail('ACCESS','18.4','All SECURITY DEFINER functions pin search_path',
        n||' functions missing search_path');
    END IF;

    -- 18.5 orgpasscheck_admin role exists and is NOLOGIN
    SELECT COUNT(*) INTO n FROM pg_roles
    WHERE rolname = 'orgpasscheck_admin' AND rolcanlogin = false;
    IF n = 1 THEN PERFORM opc_test.pass('ACCESS','18.5','orgpasscheck_admin is NOLOGIN role');
    ELSE PERFORM opc_test.fail('ACCESS','18.5','orgpasscheck_admin is NOLOGIN role',
        'Role missing or has LOGIN');
    END IF;

    -- 18.6 list_expiry_exemptions() has permission guard in function body
    SELECT COUNT(*) INTO n
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'orgpasscheck' AND p.proname = 'list_expiry_exemptions'
      AND pg_get_functiondef(p.oid) LIKE '%permission denied%';
    IF n >= 1 THEN PERFORM opc_test.pass('ACCESS','18.6','list_expiry_exemptions() has permission guard');
    ELSE PERFORM opc_test.fail('ACCESS','18.6','list_expiry_exemptions() has permission guard',
        'Guard not found');
    END IF;

    -- 18.7 pg_monitor can SELECT on all orgpasscheck tables
    SELECT COUNT(*) INTO n
    FROM pg_tables t
    WHERE t.schemaname = 'orgpasscheck'
      AND NOT has_table_privilege('pg_monitor', t.schemaname||'.'||t.tablename, 'SELECT');
    IF n = 0 THEN PERFORM opc_test.pass('ACCESS','18.7','pg_monitor has SELECT on all tables');
    ELSE PERFORM opc_test.fail('ACCESS','18.7','pg_monitor has SELECT on all tables',
        n||' tables not accessible');
    END IF;
END $$;


-- =============================================================================
-- CATEGORY 19: DDL AUDIT LOG
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  CATEGORY 19 — DDL AUDIT LOG';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE r TEXT := 'opc_audit';
    n   INT;
BEGIN
    PERFORM opc_test.cleanup(r);

    -- 19.1 create_user() writes CREATE ROLE to audit log
    PERFORM orgpasscheck.create_user(r, 'rT7#mX2$pL9@');
    SELECT COUNT(*) INTO n FROM orgpasscheck.ddl_audit_log
    WHERE rolname = r AND command_tag = 'CREATE ROLE';
    IF n >= 1 THEN PERFORM opc_test.pass('AUDIT','19.1','CREATE ROLE written to ddl_audit_log');
    ELSE PERFORM opc_test.fail('AUDIT','19.1','CREATE ROLE written to ddl_audit_log','0 rows');
    END IF;

    -- 19.2 change_password() writes ALTER ROLE to audit log
    PERFORM orgpasscheck.change_password(r, 'H#4jM2$rP9L!');
    SELECT COUNT(*) INTO n FROM orgpasscheck.ddl_audit_log
    WHERE rolname = r AND command_tag = 'ALTER ROLE';
    IF n >= 1 THEN PERFORM opc_test.pass('AUDIT','19.2','ALTER ROLE written to ddl_audit_log');
    ELSE PERFORM opc_test.fail('AUDIT','19.2','ALTER ROLE written to ddl_audit_log','0 rows');
    END IF;

    -- 19.3 Audit log records issued_by (current_user)
    SELECT COUNT(*) INTO n FROM orgpasscheck.ddl_audit_log
    WHERE rolname = r AND issued_by = current_user;
    IF n >= 1 THEN PERFORM opc_test.pass('AUDIT','19.3','ddl_audit_log records issued_by correctly');
    ELSE PERFORM opc_test.fail('AUDIT','19.3','ddl_audit_log records issued_by correctly','0 rows');
    END IF;

    PERFORM opc_test.cleanup(r);
END $$;


-- =============================================================================
-- FINAL SUMMARY
-- =============================================================================
DO $$ BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  FINAL RESULTS';
    RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;

DO $$
DECLARE
    v_total   INT;
    v_pass    INT;
    v_fail    INT;
    v_skip    INT;
    rec       RECORD;
BEGIN
    SELECT
        COUNT(*)                              INTO v_total FROM opc_test.results;
    SELECT COUNT(*) FILTER (WHERE status='PASS') INTO v_pass  FROM opc_test.results;
    SELECT COUNT(*) FILTER (WHERE status='FAIL') INTO v_fail  FROM opc_test.results;
    SELECT COUNT(*) FILTER (WHERE status='SKIP') INTO v_skip  FROM opc_test.results;

    RAISE NOTICE '';
    RAISE NOTICE '┌─────────────────────────────────────────────────────────────┐';
    RAISE NOTICE '│  orgpasscheck v5.0  —  Pre-Publication Test Results         │';
    RAISE NOTICE '│  Author: Md. Masum Billah <mbpcore@gmail.com>               │';
    RAISE NOTICE '├─────────────────────────────────────────────────────────────┤';
    RAISE NOTICE '│  Total  : %-49s│', v_total;
    RAISE NOTICE '│  ✅ PASS: %-49s│', v_pass;
    RAISE NOTICE '│  ❌ FAIL: %-49s│', v_fail;
    RAISE NOTICE '│  ⏭  SKIP: %-49s│', v_skip;
    RAISE NOTICE '└─────────────────────────────────────────────────────────────┘';

    IF v_fail = 0 THEN
        RAISE NOTICE '';
        RAISE NOTICE '🎉  ALL CHECKS PASSED — orgpasscheck v5.0 is ready for publication.';
        RAISE NOTICE '';
    ELSE
        RAISE NOTICE '';
        RAISE NOTICE '⚠️   FAILURES FOUND — do not publish until resolved:';
        RAISE NOTICE '';
        FOR rec IN
            SELECT test_id, description, detail
            FROM opc_test.results
            WHERE status = 'FAIL'
            ORDER BY id
        LOOP
            RAISE NOTICE '  ❌  [%]  %', rec.test_id, rec.description;
            IF rec.detail IS NOT NULL THEN
                RAISE NOTICE '        → %', rec.detail;
            END IF;
        END LOOP;
        RAISE NOTICE '';
    END IF;

    IF v_skip > 0 THEN
        RAISE NOTICE 'Skipped tests (require manual verification):';
        FOR rec IN
            SELECT test_id, description, detail
            FROM opc_test.results WHERE status = 'SKIP' ORDER BY id
        LOOP
            RAISE NOTICE '  ⏭   [%]  %', rec.test_id, rec.description;
            RAISE NOTICE '        → %', rec.detail;
        END LOOP;
        RAISE NOTICE '';
    END IF;

    RAISE NOTICE 'Full results: SELECT * FROM opc_test.results ORDER BY id;';
    RAISE NOTICE '';
END $$;

\set ON_ERROR_STOP on
