# Contributing

I welcome improvements via issues and pull requests. Please adhere to the following:

- Discuss significant changes via an issue before opening a PR.
- Fork and create feature branches: `feat/...`, `fix/...`, `docs/...`.
- Keep changes focused and include tests for new functionality.
- Run linters and formatters; ensure Terraform is formatted (`terraform fmt -check`) and validated (`terraform validate`).
- For security-related changes, document threat model updates in `docs/`.

## Commit Messages

Follow Conventional Commits:

- `feat:` new functionality
- `fix:` bug fixes
- `docs:` documentation only changes
- `chore:` build or tooling updates
- `refactor:` code changes that neither fix a bug nor add a feature

## Code Style

- Python: type hints, `ruff` for linting, `black` for formatting, `mypy` for typing.
- Terraform: `terraform fmt`, pin providers, avoid implicit dependencies.

## PR Checklist

- [ ] Unit tests added/updated
- [ ] Security considerations noted
- [ ] Docs updated
- [ ] CI passing (lint, tests, terraform validate)