# Contributing

Thanks for your interest in contributing to `wxccs/radius`. This document
describes the workflow for bug reports, feature work, and pull requests.

## Development Environment

- Go 1.26+ (see `go.mod` for the exact version pinned in CI)
- `golangci-lint` (latest stable)
- Network access to `proxy.golang.org` for module downloads

## Workflow

1. Fork the repository and create a feature branch:
   ```sh
   git checkout -b feat/<short-description>
   ```
   Use `feat/`, `fix/`, `docs/`, `refactor/`, or `test/` prefixes.
2. Make your changes. Every new `.go` file MUST start with:
   ```go
   // SPDX-License-Identifier: MIT
   ```
3. Format and vet:
   ```sh
   gofmt -w .
   go vet ./...
   ```
4. Run lint:
   ```sh
   golangci-lint run
   ```
5. Run tests with race detection and coverage:
   ```sh
   go test -race -coverprofile=coverage.out -covermode=atomic ./...
   go tool cover -func=coverage.out
   ```
   The project-wide coverage target is 90% or higher. Do not lower the
   threshold without discussion.
6. Keep commits focused and write messages in English, using the format
   `type(scope): description`. Examples:
   - `feat(packet): encode Access-Request authenticator`
   - `fix(crypto): validate User-Password block length`
7. Open a pull request against `main`. Provide an English description that
   explains the why, links any related issues, and lists manual verification
   steps taken.

## Code Style

- Follow `gofmt` and `golangci-lint` defaults.
- No `panic` in library code except `init` for unrecoverable setup errors.
- Errors are wrapped with `fmt.Errorf("...: %w", err)` at boundaries.
- Exported identifiers require GoDoc comments beginning with the identifier
  name.

## Commit Message Convention

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `build`.

## License

By contributing, you agree that your contributions are licensed under the MIT
License, as described in [LICENSE](LICENSE).
