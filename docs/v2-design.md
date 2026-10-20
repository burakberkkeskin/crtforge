# crtforge v2: why and what changed

Decision record for the v2 rewrite (2026-10). The current behaviour is described in [architecture.md](architecture.md); this file keeps the reasons.

## Why rewrite

v1 produced working chains for browsers, but an analysis of v1.10.0 found problems that were cheaper to fix with a rewrite than with patches:

| Problem in v1 | Effect |
|---|---|
| No CRL Distribution Point or AIA on intermediates and leaves | Clients that check revocation (MailKit / .NET, Windows Schannel) reject the chain with "unable to get certificate CRL", even when the root is trusted |
| The intermediate key Go generated (RSA 4096) was overwritten by `openssl req -keyout` with a new 2048-bit key | The intermediate was weaker than intended; the code silently depended on the overwrite (PKCS #8 parsing) |
| CA private keys written `0644`, config files `0755` | Only the `0700` parent directory protected the keys |
| macOS `--trust` set `com.apple.trust-settings.admin` to `allow`, then removed the right; an error in between left it at `allow` | Any process could change system trust settings without authentication |
| Linux `--trust` copied the root but never ran `update-ca-certificates` / `update-ca-trust`, and ignored the error | Trust silently did not happen |
| `-b/--basicconstraints` only changed unused OpenSSL config sections | The flag had no effect, although the README suggested `-b CA:TRUE` |
| OpenSSL configs rendered with `html/template` | `&` became `&amp;`; values could inject config lines |
| Subject attributes applied only when a CA was first created; a mismatching country later failed with a bare `exit status 1` | Silent or opaque behaviour |
| Same root DN (`CN=Crtforge ROOT CA`) for every CA | Distinct roots indistinguishable by name on one machine |
| `crtforge <app>` without a domain panicked; the same app name silently overwrote key and certificate | |
| Half Go, half `os/exec openssl`; `log.Fatal` everywhere; no tests; Dockerfile and CI on different Go versions; Linux arm64 asset named `arm64` while `uname -m` reports `aarch64` | Hard to change safely; the install one-liner failed on Linux ARM |

Alternatives considered: mkcert (no intermediate, no CRL), step CLI (CRLs need the step-ca server), easy-rsa (bash + OpenSSL, clunky), cfssl (heavy, slowing maintenance). crtforge's value is a one-command chain for labs, and a pure-Go rewrite of about 1,000 lines kept that.

## Decisions

| Topic | Decision | Reason |
|---|---|---|
| Implementation | Pure Go `crypto/x509`, no `openssl` | One code path, testable, no runtime dependency |
| Revocation | CDP and AIA on intermediates and leaves when the CA has a base URL; CRLs per issuer; `revoke` and `crl` commands | Strict clients need a CRL that is reachable, signed by the issuer and not expired; `revoke` lets a lab test revoked-certificate handling |
| CRL transport | Plain HTTP, DER files from a publish directory; crtforge does not serve them | RFC 5280 practice, avoids a TLS dependency on the CRL fetch; any static web server works |
| CRL validity | 365 days by default, warnings 30 days ahead | In a lab an expired CRL looks like a bug in the system under test |
| OCSP | Not supported | CRLs cover the clients that check revocation in practice; OCSP needs a running responder |
| Trust stores | Removed; `inspect` prints the commands | Privileged, hard-to-undo system changes do not belong in a certificate generator |
| Output | certbot names; `fullchain.pem` = leaf + intermediate; root in `ca.pem` | The conventions servers and operators already know; servers should not send the root |
| Leaf validity | 397 days default, 825 max | 825 days is Apple's limit for TLS server certificates, private CAs included |
| v1 compatibility | None in the CLI; `import-v1` keeps a trusted v1 root and issues a new intermediate under it | Avoids re-trusting machines while dropping v1's interface |
| Data directory | `$XDG_DATA_HOME/crtforge` (`~/.local/share/crtforge`) | Keys are data, not config; v1's `~/.config/crtforge` stays untouched for rollback |
| Distribution | Static binaries for Linux and macOS on amd64 / arm64 with `SHA256SUMS`; Docker image dropped | The container added nothing over a static binary |
| Quality gates | Unit tests, OpenSSL interop test (verify + revoke), zlint (RFC sources), staticcheck, govulncheck, actions pinned by commit SHA | Certificates are checked against a second implementation and a linter, not only against Go |
