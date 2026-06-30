/*-------------------------------------------------------------------------
 * orgpasscheck.c
 *
 * Enterprise Password Policy Enforcement Extension for PostgreSQL 16+
 *
 * Author:   Md. Masum Billah <mbpcore@gmail.com>
 * Version:  5.0
 * License:  PostgreSQL License
 *
 * Description:
 *   Enforces configurable password complexity, history reuse prevention,
 *   dictionary and blacklist checks, minimum age, and expiry policy via
 *   PostgreSQL's native check_password_hook.  Every CREATE ROLE and
 *   ALTER ROLE ... PASSWORD statement is intercepted at the C level so
 *   no DDL path can bypass the policy.
 *
 * Requirements:
 *   PostgreSQL 16 or later.  No external dependencies.
 *
 * Build:
 *   make PG_CONFIG=/usr/pgsql-16/bin/pg_config
 *   sudo make install
 *
 * postgresql.conf:
 *   shared_preload_libraries = 'orgpasscheck'
 *
 * First use:
 *   CREATE SCHEMA orgpasscheck;
 *   CREATE EXTENSION orgpasscheck;
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "commands/user.h"
#include "utils/guc.h"
#include "executor/spi.h"
#include "utils/timestamp.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "catalog/pg_type.h"
#include <ctype.h>
#include <string.h>
#include <limits.h>

PG_MODULE_MAGIC;

/* ------------------------------------------------------------------ */
/* GUC variables                                                        */
/* ------------------------------------------------------------------ */

static int   orgpasscheck_min_length           = 12;
static int   orgpasscheck_min_upper            = 1;
static int   orgpasscheck_min_lower            = 1;
static int   orgpasscheck_min_digit            = 1;
static int   orgpasscheck_min_special          = 1;
static bool  orgpasscheck_require_mixed_case   = true;
static bool  orgpasscheck_require_seq_check    = true;
static bool  orgpasscheck_reject_username      = true;
static bool  orgpasscheck_similarity_check     = true;
static int   orgpasscheck_similarity_threshold = 3;
static bool  orgpasscheck_dictionary_check     = true;
static bool  orgpasscheck_blacklist_check      = true;
static int   orgpasscheck_reuse_history        = 5;
static int   orgpasscheck_min_age_days         = 1;
static int   orgpasscheck_expiry_days          = 45;
static bool  orgpasscheck_enforce_expiry       = true;
static bool  orgpasscheck_allow_no_expiry      = false;

/* ------------------------------------------------------------------ */
/* Hook chain                                                           */
/* ------------------------------------------------------------------ */

static check_password_hook_type prev_check_password_hook = NULL;

void _PG_init(void);
void _PG_fini(void);

static void orgpasscheck_hook(const char *username,
                              const char *password,
                              PasswordType password_type,
                              Datum validuntil_datum,
                              bool validuntil_null);

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * str_to_lower_palloc
 * Returns a palloc'd lowercase copy of src.
 */
static char *
str_to_lower_palloc(const char *src)
{
    size_t  len = strlen(src);
    char   *dst = (char *) palloc(len + 1);
    size_t  i;

    for (i = 0; i < len; i++)
        dst[i] = (char) tolower((unsigned char) src[i]);
    dst[len] = '\0';
    return dst;
}

/*
 * levenshtein_distance
 * Standard Wagner-Fischer DP.  Returns INT_MAX for inputs longer than
 * MAX_LEV_INPUT to avoid O(n^2) cost and integer overflow.
 */
#define MAX_LEV_INPUT 256

static int
levenshtein_distance(const char *s1, const char *s2)
{
    int  len1 = (int) strlen(s1);
    int  len2 = (int) strlen(s2);
    int *d;
    int  i, j, cost, result;
    int  del, ins, sub, mn;

    if (len1 > MAX_LEV_INPUT || len2 > MAX_LEV_INPUT)
        return INT_MAX;

    d = (int *) palloc((len1 + 1) * (len2 + 1) * sizeof(int));

    for (i = 0; i <= len1; i++) d[i * (len2 + 1)]     = i;
    for (j = 0; j <= len2; j++) d[j]                   = j;

    for (i = 1; i <= len1; i++)
    {
        for (j = 1; j <= len2; j++)
        {
            cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            del  = d[(i - 1) * (len2 + 1) + j]     + 1;
            ins  = d[ i      * (len2 + 1) + j - 1] + 1;
            sub  = d[(i - 1) * (len2 + 1) + j - 1] + cost;
            mn   = del;
            if (ins < mn) mn = ins;
            if (sub < mn) mn = sub;
            d[i * (len2 + 1) + j] = mn;
        }
    }
    result = d[len1 * (len2 + 1) + len2];
    pfree(d);
    return result;
}

/* ------------------------------------------------------------------ */
/* The password hook                                                    */
/* ------------------------------------------------------------------ */

static void
orgpasscheck_hook(const char *username,
                  const char *password,
                  PasswordType password_type,
                  Datum validuntil_datum,
                  bool validuntil_null)
{
    const char *safe_user;
    char       *lower_pw;
    char       *lower_user;
    int         pw_len;
    int         upper_cnt   = 0;
    int         lower_cnt   = 0;
    int         digit_cnt   = 0;
    int         special_cnt = 0;
    int         i;
    int         lev_dist;

    /* Skip NULL / empty passwords (e.g. NOLOGIN roles) */
    if (password == NULL || password[0] == '\0')
        return;

    pw_len    = (int) strlen(password);
    safe_user = (username != NULL && username[0] != '\0') ? username : "<unknown>";

    /* ------------------------------------------------------------------
     * GUARD: pre-hashed passwords cannot be evaluated for policy.
     * Clients must send plaintext (password_encryption = scram-sha-256).
     * ------------------------------------------------------------------ */
    if (password_type != PASSWORD_TYPE_PLAINTEXT)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must be supplied as plaintext "
                        "so that policy checks can be performed. "
                        "Set password_encryption = 'scram-sha-256' on the "
                        "client and resend the password.")));

    /* ------------------------------------------------------------------
     * 1. LENGTH
     * ------------------------------------------------------------------ */
    if (pw_len < orgpasscheck_min_length)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password is too short "
                        "(minimum %d characters required, got %d).",
                        orgpasscheck_min_length, pw_len)));

    /* ------------------------------------------------------------------
     * 2. CHARACTER CLASS COUNTS
     * ------------------------------------------------------------------ */
    for (i = 0; i < pw_len; i++)
    {
        unsigned char c = (unsigned char) password[i];
        if      (isupper(c)) upper_cnt++;
        else if (islower(c)) lower_cnt++;
        else if (isdigit(c)) digit_cnt++;
        else                 special_cnt++;
    }

    if (upper_cnt < orgpasscheck_min_upper)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must contain at least %d "
                        "uppercase letter(s) (found %d).",
                        orgpasscheck_min_upper, upper_cnt)));

    if (lower_cnt < orgpasscheck_min_lower)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must contain at least %d "
                        "lowercase letter(s) (found %d).",
                        orgpasscheck_min_lower, lower_cnt)));

    if (digit_cnt < orgpasscheck_min_digit)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must contain at least %d "
                        "digit(s) (found %d).",
                        orgpasscheck_min_digit, digit_cnt)));

    if (special_cnt < orgpasscheck_min_special)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must contain at least %d "
                        "special character(s) (found %d).",
                        orgpasscheck_min_special, special_cnt)));

    if (orgpasscheck_require_mixed_case && (upper_cnt == 0 || lower_cnt == 0))
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("orgpasscheck: password must contain both uppercase "
                        "and lowercase letters.")));

    /* ------------------------------------------------------------------
     * 3. SEQUENTIAL PATTERN CHECK
     *    Blocks 3+ identical chars (aaa), 3+ ascending (abc, 123),
     *    and 3+ descending (zyx, 321).
     * ------------------------------------------------------------------ */
    if (orgpasscheck_require_seq_check && pw_len >= 3)
    {
        for (i = 0; i <= pw_len - 3; i++)
        {
            unsigned char c0 = (unsigned char) password[i];
            unsigned char c1 = (unsigned char) password[i + 1];
            unsigned char c2 = (unsigned char) password[i + 2];

            if (c0 == c1 && c1 == c2)
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("orgpasscheck: password must not contain "
                                "3 or more identical consecutive characters.")));

            if ((c1 == c0 + 1 && c2 == c0 + 2) ||
                (c1 == c0 - 1 && c2 == c0 - 2))
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("orgpasscheck: password must not contain "
                                "sequential ascending or descending character "
                                "runs (e.g. 'abc', '123', 'zyx').")));
        }
    }

    /* Build lowercase copies once for all case-insensitive checks below */
    lower_pw   = str_to_lower_palloc(password);
    lower_user = str_to_lower_palloc(safe_user);

    /* ------------------------------------------------------------------
     * 4. USERNAME CONTAINMENT (case-insensitive)
     * ------------------------------------------------------------------ */
    if (orgpasscheck_reject_username && username != NULL)
    {
        if (strstr(lower_pw, lower_user) != NULL)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("orgpasscheck: password must not contain "
                            "your username.")));
    }

    /* ------------------------------------------------------------------
     * 5. LEVENSHTEIN SIMILARITY (case-insensitive)
     *    Rejects if edit distance <= similarity_threshold.
     *    Lower threshold = less strict; threshold=0 = only rejects identical.
     * ------------------------------------------------------------------ */
    if (orgpasscheck_similarity_check && username != NULL)
    {
        lev_dist = levenshtein_distance(lower_pw, lower_user);
        if (lev_dist <= orgpasscheck_similarity_threshold)
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("orgpasscheck: password is too similar to your "
                            "username (edit distance %d, threshold %d).",
                            lev_dist, orgpasscheck_similarity_threshold)));
    }

    /* Chain any previously registered hook */
    if (prev_check_password_hook)
        prev_check_password_hook(username, password, password_type,
                                 validuntil_datum, validuntil_null);

    /* ------------------------------------------------------------------
     * SPI-based checks: blacklist, dictionary, minimum age, history reuse.
     * PG_TRY guarantees SPI_finish() is always called even on error.
     * IMPORTANT: Do NOT call SPI_finish() before ereport(ERROR) inside
     * this block. Double-close corrupts the SPI stack and crashes the
     * backend (SIGSEGV). Let PG_CATCH be the sole error-path closer.
     * ------------------------------------------------------------------ */
    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR,
                (errmsg("orgpasscheck: could not connect to SPI.")));

    PG_TRY();
    {
        Oid   txt1[1] = { TEXTOID };
        Datum val1[1];
        Oid   txt2[2] = { TEXTOID, INT4OID };
        Datum val2[2];

        /* ── 6. BLACKLIST — substring match ────────────────────────── */
        if (orgpasscheck_blacklist_check)
        {
            static const char *bl_sql =
                "SELECT 1 FROM orgpasscheck.password_blacklist "
                "WHERE  $1 LIKE '%' || blacklisted_word || '%' ESCAPE '\\' "
                "  AND  (expires_at IS NULL OR expires_at > now()) "
                "LIMIT  1";

            val1[0] = CStringGetTextDatum(lower_pw);

            if (SPI_execute_with_args(bl_sql, 1, txt1, val1,
                                      NULL, true, 1) == SPI_OK_SELECT
                && SPI_processed > 0)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("orgpasscheck: password contains a pattern "
                                "that is explicitly blacklisted by your "
                                "organisation.")));
            }
        }

        /* ── 7. DICTIONARY — substring match ───────────────────────── */
        if (orgpasscheck_dictionary_check)
        {
            static const char *dict_sql =
                "SELECT 1 FROM orgpasscheck.password_dictionary "
                "WHERE  $1 LIKE '%' || word || '%' ESCAPE '\\' "
                "LIMIT  1";

            val1[0] = CStringGetTextDatum(lower_pw);

            if (SPI_execute_with_args(dict_sql, 1, txt1, val1,
                                      NULL, true, 1) == SPI_OK_SELECT
                && SPI_processed > 0)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("orgpasscheck: password contains a common "
                                "dictionary word and cannot be used.")));
            }
        }

        /* ── 8. MINIMUM AGE ─────────────────────────────────────────── */
        if (orgpasscheck_min_age_days > 0 && username != NULL && username[0] != '\0')
        {
            static const char *age_sql =
                "SELECT FLOOR(EXTRACT(EPOCH FROM (now() - changed_at)) / 86400)::int "
                "FROM   orgpasscheck.password_history "
                "WHERE  username = $1 "
                "ORDER  BY seq DESC LIMIT 1";

            bool isnull;
            int  days_diff;

            val1[0] = CStringGetTextDatum(safe_user);

            if (SPI_execute_with_args(age_sql, 1, txt1, val1,
                                      NULL, true, 1) == SPI_OK_SELECT
                && SPI_processed > 0)
            {
                days_diff = DatumGetInt32(
                    SPI_getbinval(SPI_tuptable->vals[0],
                                  SPI_tuptable->tupdesc, 1, &isnull));
                if (!isnull && days_diff < orgpasscheck_min_age_days)
                {
                    ereport(ERROR,
                            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                             errmsg("orgpasscheck: password was changed %d "
                                    "day(s) ago. You must wait %d day(s) "
                                    "before changing it again.",
                                    days_diff, orgpasscheck_min_age_days)));
                }
            }
        }

        /* ── 9. HISTORY REUSE ──────────────────────────────────────── */
        if (orgpasscheck_reuse_history > 0 && username != NULL && username[0] != '\0')
        {
            static const char *hist_sql =
                "SELECT password_hash, salt "
                "FROM   orgpasscheck.password_history "
                "WHERE  username = $1 "
                "ORDER  BY seq DESC LIMIT $2";

            int    rows   = 0;
            char **hashes = NULL;
            char **salts  = NULL;

            val2[0] = CStringGetTextDatum(safe_user);
            val2[1] = Int32GetDatum(orgpasscheck_reuse_history);

            if (SPI_execute_with_args(hist_sql, 2, txt2, val2,
                                      NULL, true, 0) == SPI_OK_SELECT
                && SPI_processed > 0)
            {
                /*
                 * Phase A: copy hash+salt before any nested SPI call
                 * clobbers SPI_tuptable.
                 */
                rows   = (int) SPI_processed;
                hashes = (char **) palloc(rows * sizeof(char *));
                salts  = (char **) palloc(rows * sizeof(char *));

                for (i = 0; i < rows; i++)
                {
                    char *h = SPI_getvalue(SPI_tuptable->vals[i],
                                           SPI_tuptable->tupdesc, 1);
                    char *s = SPI_getvalue(SPI_tuptable->vals[i],
                                           SPI_tuptable->tupdesc, 2);
                    hashes[i] = h ? pstrdup(h) : NULL;
                    salts[i]  = s ? pstrdup(s) : NULL;
                }
            }

            /* Phase B: compare each stored hash */
            for (i = 0; i < rows; i++)
            {
                Oid   vargs[3] = { TEXTOID, TEXTOID, TEXTOID };
                Datum vvals[3];
                bool  isnull;
                bool  match;

                if (!hashes[i] || !salts[i])
                    continue;

                vvals[0] = CStringGetTextDatum(password);
                vvals[1] = CStringGetTextDatum(salts[i]);
                vvals[2] = CStringGetTextDatum(hashes[i]);

                if (SPI_execute_with_args(
                        "SELECT orgpasscheck.verify_password_hash($1,$2,$3)",
                        3, vargs, vvals, NULL, true, 1) == SPI_OK_SELECT
                    && SPI_processed > 0)
                {
                    match = DatumGetBool(
                        SPI_getbinval(SPI_tuptable->vals[0],
                                      SPI_tuptable->tupdesc, 1, &isnull));
                    if (!isnull && match)
                    {
                        ereport(ERROR,
                                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                                 errmsg("orgpasscheck: password was used "
                                        "recently. You cannot reuse any of "
                                        "your last %d passwords.",
                                        orgpasscheck_reuse_history)));
                    }
                }
            }
        }

        /* ── 10. RECORD NEW PASSWORD IN HISTORY ─────────────────────── */
        if (username != NULL && username[0] != '\0')
        {
            static const char *ins_sql =
                "INSERT INTO orgpasscheck.password_history "
                "       (username, password_hash, salt) "
                "SELECT $1, "
                "       encode(sha256((s.salt || $2)::bytea), 'hex'), "
                "       s.salt "
                "FROM   (SELECT replace(gen_random_uuid()::text,'-','') "
                "               AS salt) s";

            Oid   iargs[2] = { TEXTOID, TEXTOID };
            Datum ivals[2];
            int   rc;

            ivals[0] = CStringGetTextDatum(safe_user);
            ivals[1] = CStringGetTextDatum(password);

            rc = SPI_execute_with_args(ins_sql, 2, iargs, ivals,
                                       NULL, false, 0);
            if (rc != SPI_OK_INSERT)
                ereport(WARNING,
                        (errmsg("orgpasscheck: failed to record password "
                                "history for \"%s\" (SPI %d: %s).",
                                safe_user, rc,
                                SPI_result_code_string(rc))));
        }

        /* ── 11. PRUNE OLD HISTORY ──────────────────────────────────── */
        if (orgpasscheck_reuse_history > 0 && username != NULL && username[0] != '\0')
        {
            static const char *prune_sql =
                "DELETE FROM orgpasscheck.password_history "
                "WHERE  username = $1 "
                "  AND  seq NOT IN ("
                "       SELECT seq "
                "       FROM   orgpasscheck.password_history "
                "       WHERE  username = $1 "
                "       ORDER  BY seq DESC "
                "       LIMIT  $2)";

            Oid   pargs[2] = { TEXTOID, INT4OID };
            Datum pvals[2];

            pvals[0] = CStringGetTextDatum(safe_user);
            pvals[1] = Int32GetDatum(orgpasscheck_reuse_history);

            SPI_execute_with_args(prune_sql, 2, pargs, pvals,
                                  NULL, false, 0);
        }
    }
    PG_CATCH();
    {
        SPI_finish();
        PG_RE_THROW();
    }
    PG_END_TRY();

    SPI_finish();
}

/* ------------------------------------------------------------------ */
/* _PG_init — register GUCs and install hook                           */
/* ------------------------------------------------------------------ */

void
_PG_init(void)
{
    DefineCustomIntVariable(
        "orgpasscheck.min_length",
        "Minimum password length.", NULL,
        &orgpasscheck_min_length, 12, 0, 128,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.min_upper",
        "Minimum number of uppercase letters.", NULL,
        &orgpasscheck_min_upper, 1, 0, 50,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.min_lower",
        "Minimum number of lowercase letters.", NULL,
        &orgpasscheck_min_lower, 1, 0, 50,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.min_digit",
        "Minimum number of digit characters.", NULL,
        &orgpasscheck_min_digit, 1, 0, 50,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.min_special",
        "Minimum number of special (non-alphanumeric) characters.", NULL,
        &orgpasscheck_min_special, 1, 0, 50,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.require_mixed_case",
        "Require both uppercase and lowercase letters.", NULL,
        &orgpasscheck_require_mixed_case, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.require_sequence_check",
        "Reject passwords with 3+ identical or sequential characters.", NULL,
        &orgpasscheck_require_seq_check, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.reject_username",
        "Reject passwords containing the username (case-insensitive).", NULL,
        &orgpasscheck_reject_username, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.similarity_check",
        "Reject passwords too similar to the username (Levenshtein distance).",
        NULL,
        &orgpasscheck_similarity_check, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.similarity_threshold",
        "Edit distance at or below which a password is rejected as too similar "
        "to the username. Lower = less strict; 0 = only reject identical.",
        NULL,
        &orgpasscheck_similarity_threshold, 3, 0, 20,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.dictionary_check",
        "Reject passwords containing words from password_dictionary.", NULL,
        &orgpasscheck_dictionary_check, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.blacklist_check",
        "Reject passwords containing patterns from password_blacklist.", NULL,
        &orgpasscheck_blacklist_check, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.reuse_history",
        "Number of previous passwords that cannot be reused (0 = disabled).",
        NULL,
        &orgpasscheck_reuse_history, 5, 0, 50,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.min_age_days",
        "Minimum days before a password may be changed again (0 = disabled).",
        NULL,
        &orgpasscheck_min_age_days, 1, 0, 365,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "orgpasscheck.expiry_days",
        "Default password validity in days (enforced by SQL wrapper functions only, "
        "not by the C hook). 0 = no expiry (requires allow_no_expiry_users = on).", NULL,
        &orgpasscheck_expiry_days, 45, 0, 365,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.enforce_expiry",
        "Enable password expiry enforcement (SQL wrapper functions only; "
        "raw DDL bypasses this setting).", NULL,
        &orgpasscheck_enforce_expiry, true,
        PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "orgpasscheck.allow_no_expiry_users",
        "Allow specific users to have passwords with no expiry date "
        "(used by SQL wrapper functions only).", NULL,
        &orgpasscheck_allow_no_expiry, false,
        PGC_SUSET, 0, NULL, NULL, NULL);

    prev_check_password_hook = check_password_hook;
    check_password_hook      = orgpasscheck_hook;
}

/* ------------------------------------------------------------------ */
/* _PG_fini — restore previous hook on unload                          */
/* ------------------------------------------------------------------ */

void
_PG_fini(void)
{
    check_password_hook = prev_check_password_hook;
}
