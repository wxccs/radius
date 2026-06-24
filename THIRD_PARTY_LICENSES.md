# Third-Party Licenses

This project (`wxccs/radius`) is licensed under the [MIT License](LICENSE).
However, its dependencies retain their own licenses, which are enumerated
below.

The table is generated and refreshed by `go-licenses` during CI. Manual edits
should be limited to adding SPDX identifiers when a dependency lacks machine-
readable license metadata.

| Module | Version | License (SPDX) | Source |
|--------|---------|----------------|--------|
| github.com/stretchr/testify | v1.10.0 | MIT | https://github.com/stretchr/testify |
| github.com/davecgh/go-spew | v1.1.1 | ISC | https://github.com/davecgh/go-spew |
| github.com/pmezard/go-difflib | v1.0.0 | BSD-3-Clause | https://github.com/pmezard/go-difflib |
| github.com/stretchr/objx | v0.5.0 | MIT | https://github.com/stretchr/objx |
| gopkg.in/yaml.v3 | v3.0.1 | MIT | https://github.com/go-yaml/yaml |

> The versions above are placeholders pending the first `go mod tidy` run; the
> CI job that runs `go-licenses report ./...` will surface the exact versions
> resolved for the current `go.sum`.
