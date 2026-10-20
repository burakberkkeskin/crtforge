# Usage

Walkthroughs for common setups. Every command takes `--ca <name>` (or `$CRTFORGE_CA`) and `--home <dir>` (or `$CRTFORGE_HOME`); the examples set the CA once:

```bash
export CRTFORGE_CA=lab
```

## A lab CA with revocation

```bash
crtforge init --base-url http://pki.example.test
crtforge issue gitlab gitlab.example.test registry.example.test
crtforge issue nexus nexus.example.test
rsync -a ~/.local/share/crtforge/publish/ webhost:/srv/pki/
```

Check that the CRL answers before pointing clients at the certificates:

```bash
curl -fsS http://pki.example.test/lab/int1.crl | openssl crl -inform DER -noout -issuer -nextupdate
```

Configure the server with `certs/<name>/fullchain.pem` and `certs/<name>/privkey.pem`, and give clients `ca.pem`.

## Trusting the root

crtforge prints the trust commands and leaves running them to you:

```bash
crtforge inspect
```

```
  macOS          sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '.../root/cert.pem'
  Debian/Ubuntu  sudo cp '.../root/cert.pem' /usr/local/share/ca-certificates/crtforge-lab.crt && sudo update-ca-certificates
  RHEL/Fedora    sudo cp '.../root/cert.pem' /etc/pki/ca-trust/source/anchors/crtforge-lab.crt && sudo update-ca-trust
  Java           keytool -importcert -noprompt -alias crtforge-lab -file '.../root/cert.pem' -keystore <truststore> -storepass <password>
```

Compare the SHA-256 fingerprint `inspect` shows with the one on the client before trusting a copied file.

## Wildcards and IP addresses

```bash
crtforge issue web "*.apps.example.test" apps.example.test 192.0.2.10
```

A wildcard covers one label (`a.apps.example.test`, not `a.b.apps.example.test`) and must be followed by at least two labels. Quote it so the shell does not expand it.

## Testing a revoked certificate

```bash
crtforge issue revoked-demo demo.example.test
crtforge revoke revoked-demo --reason keyCompromise
rsync -a ~/.local/share/crtforge/publish/ webhost:/srv/pki/
```

Clients that check revocation now reject `demo.example.test`. `crtforge renew revoked-demo` issues a fresh certificate with the same names.

## Keeping CRLs fresh

CRLs are valid for `--crl-days` (default 365). Before the next update shown by `crtforge list`, re-sign them and publish them again:

```bash
crtforge crl
rsync -a ~/.local/share/crtforge/publish/ webhost:/srv/pki/
```

An expired CRL breaks TLS for every client that checks revocation, so schedule this if the CA lives long.

## Restricting what the CA can sign

Name constraints on the intermediate keep a trusted lab root from vouching for real domains:

```bash
crtforge init --base-url http://pki.example.test --permit-dns example.test --permit-ip 10.0.0.0/8
crtforge issue web www.example.com   # refused: outside the constraints
```

`add-intermediate` takes the same flags, so one root can have a constrained and an unconstrained intermediate:

```bash
crtforge add-intermediate internal --permit-dns corp.test
crtforge issue api api.corp.test --intermediate internal
```

## PKCS #12 for Java and Windows

```bash
crtforge issue tomcat tomcat.example.test --pfx --pfx-password changeit
```

The default uses AES-256 and PBKDF2. Java 8 before 8u301 and Windows Server 2016 cannot read that; add `--pfx-legacy` for 3DES/SHA-1.

## Client certificates (mTLS)

```bash
crtforge issue client1 client1.example.test --client
```

The certificate gets both `serverAuth` and `clientAuth`.

## ECDSA

```bash
crtforge init --ca lab-ec --key-type ecdsa --base-url http://pki.example.test
```

CA keys use P-384 and leaf keys P-256. The key type is fixed per CA.

## Keeping a v1 root

```bash
crtforge import-v1 --ca mylab --base-url http://pki.example.test ~/.config/crtforge/mylab
crtforge issue --ca mylab web app.example.test
```

The v1 root certificate and key are copied unchanged; `~/.config/crtforge` is only read. Leaf certificates from v1 stay valid but have no CRL Distribution Point; re-issue them with v2 where a client checks revocation.
