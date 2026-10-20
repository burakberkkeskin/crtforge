# Development

## Prerequisites

- Go, the version in `go.mod` or newer (CI builds with the latest 1.27 patch).
- `openssl` (optional): enables the interop test that checks chains and CRLs with `openssl verify -crl_check_all`. OpenSSL 3+ and LibreSSL both pass.

## Build

```bash
go build -o crtforge .
./crtforge --version     # dev+<commit> for local builds
```

Releases set the version with `-ldflags "-X main.version=vX.Y.Z"`.

## Test

```bash
go test -race ./...
go vet ./...
gofmt -l .
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

CI (`.github/workflows/ci.yml`) runs these on Linux and macOS. It also issues RSA and ECDSA chains and lints them with zlint's RFC 5280 / 5480 / 5891 sources. The CA/Browser Forum sources are left out, because they assume a public CA (certificate policies, public TLDs, 200-day validity).

To try commands without touching your real CAs, point `CRTFORGE_HOME` at a temporary directory.

## Code layout

See [architecture.md](architecture.md). Keep crypto in `internal/pki` (no filesystem), disk and state in `internal/ca`, flags and output in `internal/cli`. Return errors and let `cli.Execute` print them; nothing calls `os.Exit` or `log.Fatal` below `main`.

## Contribution workflow

1. Open or pick a GitHub issue.
2. Branch from `master`: `feature/<name>`, `bugfix/<issue>-<desc>` or `hotfix/<desc>`.
3. Run the checks above.
4. Open a PR against `master` with `Closes #<id>`.

## Release

Push a semver tag; CI tests, builds and publishes the release:

```bash
git checkout master && git pull
git tag --sign v2.0.0 -m "v2.0.0"
git push origin v2.0.0
```

The release job builds `crtforge-{Linux-x86_64,Linux-aarch64,Darwin-x86_64,Darwin-arm64}` (named after `uname -s`-`uname -m`, which the install one-liner uses) with `CGO_ENABLED=0 -trimpath`, writes `SHA256SUMS`, and creates the GitHub release with generated notes. Tags with a pre-release suffix (`v2.1.0-rc1`) are published as pre-releases.
