# crtforge

crtforge is a small private certificate authority for test and lab environments. One command creates a root CA and an intermediate; another issues a TLS certificate signed by that intermediate, along with its full chain.

The certificates carry CRL Distribution Points and Authority Information Access (AIA), so clients that check revocation accept them too. Some .NET stacks, MailKit for example, keep revocation checking on and reject a private chain that has no CRL.

- Root → intermediate → leaf, built in Go with no `openssl` dependency.
- CRLs for the root and each intermediate, plus `revoke`, so you can test revoked-certificate behaviour.
- certbot-style output: `fullchain.pem`, `privkey.pem`, `cert.pem`, `chain.pem`, plus `ca.pem` (the root).
- RSA (default) or ECDSA, optional name constraints, optional PKCS #12 (`.pfx`).
- Leaf validity is capped at 825 days, the limit Apple platforms enforce even for private CAs.
- crtforge never changes a trust store. `crtforge inspect` prints the commands for macOS, Debian/Ubuntu, RHEL/Fedora and Java.

## Install

```bash
curl -fsSL -o crtforge "https://github.com/burakberkkeskin/crtforge/releases/latest/download/crtforge-$(uname -s)-$(uname -m)" && \
  chmod +x crtforge && sudo mv crtforge /usr/local/bin/
```

Every release has a `SHA256SUMS` file. With Go installed you can also run `go install github.com/burakberkkeskin/crtforge@latest`.

## Quick start

```bash
# 1. Create a CA. The base URL is where its CRLs and CA certificates will be served.
crtforge init --ca lab --base-url http://pki.example.test

# 2. Issue a certificate (the first name becomes the common name; quote wildcards).
crtforge issue --ca lab web app.example.test "*.example.test" 10.0.0.5

# 3. Serve the publish directory at the base URL (see below).

# 4. Trust the root on the clients (crtforge prints the commands).
crtforge inspect --ca lab
```

`export CRTFORGE_CA=lab` saves typing `--ca` every time.

The certificate files land in `~/.local/share/crtforge/ca/lab/certs/web/`:

| File | Content | Use |
|---|---|---|
| `fullchain.pem` | leaf + intermediate | what a server presents (nginx `ssl_certificate`, Caddy, Traefik, ...) |
| `privkey.pem` | leaf key, PKCS #8 | the server key |
| `cert.pem` | leaf | tools that want the chain split |
| `chain.pem` | intermediate | |
| `ca.pem` | root | trust stores, `--cacert`, "CA certificate" fields |
| `cert.pfx` | key + leaf + intermediate + root | with `--pfx` (password `--pfx-password`, default `changeit`) |

## Publishing CRLs

Every certificate points at `<base-url>/<ca>/<issuer>.crl` (CRL Distribution Point) and `<base-url>/<ca>/<issuer>.crt` (AIA). crtforge writes these files to `~/.local/share/crtforge/publish/<ca>/`. Serve that directory over **plain HTTP**. HTTPS would make the CRL fetch depend on the TLS it is meant to check.

Example with Caddy (an explicit `http://` site, so Caddy does not redirect to HTTPS):

```caddyfile
http://pki.example.test {
	root * /srv/pki
	file_server
	@crl path *.crl
	header @crl Content-Type application/pkix-crl
	@crt path *.crt
	header @crt Content-Type application/pkix-cert
}
```

```bash
rsync -a ~/.local/share/crtforge/publish/ webhost:/srv/pki/
```

Some clients check revocation: .NET with `X509RevocationMode.Online`, MailKit, Windows Schannel, and Java when revocation checking is enabled. These clients download the CRL and reject the chain when it is unreachable, not signed by the issuer, or past its next update. CRLs are valid for 365 days by default (`--crl-days`). Run `crtforge crl` and publish again before they expire; `crtforge list` warns 30 days ahead.

Without `--base-url`, certificates carry no CDP or AIA. That is fine for clients that never check revocation (browsers, curl, Go), but strict clients will reject the chain.

## Commands

| Command | What it does |
|---|---|
| `init` | Create a root CA and its first intermediate (`--base-url`, `--key-type rsa\|ecdsa`, `--permit-dns`, `--permit-ip`, validity flags) |
| `issue <name> <dns-or-ip>...` | Issue a TLS certificate (`--days` up to 825, `--client` for mTLS, `--intermediate`, `--pfx`, `--force`) |
| `renew <name>` | New key and certificate with the recorded names and settings |
| `revoke <name>` | Revoke a certificate (`--reason keyCompromise\|superseded\|...`) and re-sign the CRL |
| `crl` | Re-sign every CRL of the CA with a new next update |
| `add-intermediate <name>` | Issue another intermediate under the root |
| `list [--all]` | CAs, intermediates and certificates with expiry, revocation and CRL status |
| `inspect [name]` | Paths, fingerprints and trust commands for the CA, or details of one certificate |
| `import-v1 <dir>` | Adopt a crtforge v1 root CA and issue a new intermediate under it |

Run `crtforge <command> --help` for every flag. See [docs/usage.md](docs/usage.md) for walkthroughs.

## Where data lives

`$CRTFORGE_HOME`, else `$XDG_DATA_HOME/crtforge`, else `~/.local/share/crtforge`:

```
ca/<ca>/ca.json                          settings (base URL, key type, CRL validity)
ca/<ca>/root/{cert.pem,privkey.pem,state.json}
ca/<ca>/intermediates/<name>/{cert.pem,privkey.pem,state.json}
ca/<ca>/certs/<name>/...                 the files in the table above, plus meta.json
publish/<ca>/{root,<intermediate>}.{crt,crl}
```

Private keys are `0600` and directories `0700`. Keys are not encrypted, so treat the directory as a secret and back it up as one.

## Upgrading from v1

v2 is a rewrite and does not read v1's layout. It also lives in a different directory: v1 used `~/.config/crtforge`, which v2 never touches. To keep a v1 root that machines already trust:

```bash
crtforge import-v1 --ca mylab --base-url http://pki.example.test ~/.config/crtforge/<v1-ca-name>
```

The v1 root is copied as is, so existing trust keeps working. A new intermediate with CRL Distribution Points is issued under it; re-issue leaf certificates with v2 to get CDP and AIA. Other changes since v1:

- Subcommands replace the single positional command, and `--ca` replaces `-r`.
- certbot file names replace `<app>.crt` / `<app>.key`. `fullchain.pem` no longer includes the root; the root is in `ca.pem`.
- `--trust` is gone; see `crtforge inspect`.
- The Docker image is gone.

## Documentation

- [Usage](docs/usage.md): walkthroughs for common setups.
- [Architecture](docs/architecture.md): certificate profiles, state, design decisions.
- [Development](docs/development.md): building, testing, releasing.
