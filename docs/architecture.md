# Architecture

## Packages

| Package | Responsibility |
|---|---|
| `internal/pki` | Keys, certificate profiles, CRLs, name validation. Pure functions over Go values; no filesystem. |
| `internal/ca` | A CA on disk: layout, state, locking, atomic writes, issue / renew / revoke / CRL refresh, v1 import. |
| `internal/cli` | Cobra commands and output. No crypto or file layout knowledge beyond what `ca` exposes. |

Everything uses Go's `crypto/x509`. PKCS #12 comes from `software.sslmate.com/src/go-pkcs12`. No external `openssl` is called.

## Certificate profiles

| | Root | Intermediate | Leaf |
|---|---|---|---|
| Key (RSA / ECDSA) | 4096 / P-384 | 3072 / P-384 | 2048 / P-256 |
| Validity (default) | 20 years | 10 years, within the root | 397 days, at most 825, within the intermediate |
| Basic constraints | CA, critical | CA, pathlen 0, critical | CA:FALSE, critical |
| Key usage | keyCertSign, cRLSign | keyCertSign, cRLSign | digitalSignature (+ keyEncipherment for RSA) |
| Extended key usage | none | serverAuth, clientAuth | serverAuth (+ clientAuth with `--client`) |
| CRL Distribution Point | none | root CRL | intermediate CRL |
| AIA caIssuers | none | root certificate | intermediate certificate |
| Name constraints | none | optional, critical | |
| Subject | O=Crtforge, CN=Crtforge `<ca>` Root CA | O=Crtforge, CN=Crtforge `<ca>` Intermediate CA (`<name>`) | CN = first SAN |

Common to all: SHA-256 (RSA) or SHA-384/SHA-256 (ECDSA) signatures, a 127-bit random serial, a subject key identifier (RFC 5280 method 1), an authority key identifier on everything but the root, and `notBefore` an hour in the past to absorb clock skew. The validity span (`notAfter - notBefore`) equals the requested number of days.

Every CA name is part of its certificates' subject. Two CAs never share a DN, which v1 did (`CN=Crtforge ROOT CA` for every root), so clients cannot confuse them when building a chain.

After signing, every intermediate and leaf is verified against its chain with `x509.Verify` before anything is written. A certificate that would not verify, for example one outside the intermediate's name constraints, is refused.

## CRLs

Each issuer (root and every intermediate) has an X.509 v2 CRL with an increasing CRL number and an authority key identifier. Entries carry the revocation time and a reason code (omitted for `unspecified`, as RFC 5280 recommends). Revoked certificates that have expired are dropped on the next re-sign.

A CRL is re-signed at creation, on `revoke` (that issuer only) and on `crl` (all issuers). Its next update is `--crl-days` ahead, 365 by default. That is longer than a production CA would use, on purpose: in a lab an expired CRL breaks TLS for revocation-checking clients and looks like a bug in whatever is under test.

The publish directory mirrors the URL layout, `publish/<ca>/<issuer>.{crl,crt}` ↔ `<base-url>/<ca>/<issuer>.{crl,crt}`, so a whole home's publish tree can be synced to one web root. Both files are DER, as RFC 5280 specifies for HTTP retrieval.

OCSP is not supported. CRLs cover the clients that check revocation in practice, and an OCSP responder would be a long-running service.

## State and safety

- `ca.json`: base URL, key algorithm, CRL validity, default intermediate, schema version (2).
- `<issuer>/state.json`: CRL number, next update, and every serial the issuer signed, with revocation time and reason.
- `certs/<name>/meta.json`: names and settings, used by `renew`.

Mutating commands take an exclusive `flock` on `ca/<ca>/.lock` and re-read state under the lock. Files are written to a temporary file and renamed. A leaf is built in a staging directory and swapped in with a rename, so `--force` and `renew` never leave a mix of old and new files. A failed `init` removes what it created.

Keys are PKCS #8, mode `0600`, unencrypted. Encrypted keys would need a dependency (the standard library cannot encrypt PKCS #8), and an interactive prompt does not fit scripted lab setups.

## Not in scope

- Changing trust stores: crtforge prints the commands instead of running privileged ones.
- OCSP, ACME, a server mode.
- Windows builds (`flock`, trust commands); the code compiles there but is not released.
