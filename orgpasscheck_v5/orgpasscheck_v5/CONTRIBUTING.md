# Contributing to orgpasscheck

Thank you for your interest in contributing!

## Reporting Issues

Please use [GitHub Issues](https://github.com/mbpcore/orgpasscheck/issues) to report bugs or request features.
When reporting a bug, include:
- PostgreSQL version (`SELECT version();`)
- Operating system and version
- Full error message
- Steps to reproduce

## Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run the test suite: `psql -U postgres -f orgpasscheck_complete_test_v3.sql`
5. Ensure the build is clean with no warnings: `make PG_CONFIG=/usr/pgsql-16/bin/pg_config`
6. Commit with a clear message and open a pull request

## Code Style

- Follow PostgreSQL extension coding conventions
- All C code must compile cleanly with `-Wall` — no warnings
- New SQL functions must be `SECURITY DEFINER` with `SET search_path`
- All new functionality must have corresponding test coverage in the test suite

## Author

Md. Masum Billah <mbpcore@gmail.com>
