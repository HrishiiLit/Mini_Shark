# Contributing to Mini Shark

## Branch Naming

- Feature branches: `feat/<short-description>`
- Bug‑fix branches: `fix/<short-description>`
- Test branches: `test/<short-description>`

## Commit Message Style

Follow **Conventional Commits**:

```
<type>(optional scope): <description>

[optional body]
[optional footer(s)]
```

Typical types:
- `feat:` new feature
- `fix:` bug fix
- `test:` add or modify tests
- `docs:` documentation only
- `chore:` maintenance tasks (e.g., CI, config)

## Pull Request Process

1. Open a PR against `main`.
2. Ensure CI passes (`ruff`, `black`, `pytest`).
3. At least one teammate must review and approve.
4. After merge, a release tag `v0.x-phaseY` will be created.

## Code Formatting

- Run `pre-commit run --all-files` before committing.
- Use `ruff` for linting and `black` for formatting.

## Testing

- Place test fixtures under `tests/data/`.
- Expected outputs live in `tests/expected/`.
- Run `pytest` from the repository root.
