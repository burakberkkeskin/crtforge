# 🏗 Architecture: crtforge

This document describes the internal architecture and the certificate generation flow of `crtforge`.

## 🏛 Certificate Hierarchy

`crtforge` follows a standard Three-Tier Public Key Infrastructure (PKI) model:

1.  **Root CA (Tier 1):**
    *   Self-signed.
    *   Highest level of trust.
    *   Used to sign Intermediate CAs.
2.  **Intermediate CA (Tier 2):**
    *   Signed by the Root CA.
    *   Used to sign Leaf/Application certificates.
    *   Provides an extra layer of security; if an intermediate is compromised, the root remains safe.
3.  **Application/Leaf Certificate (Tier 3):**
    *   Signed by the Intermediate CA.
    *   Used by web servers (Nginx, Apache), APIs, etc.

## ⚙️ Core Logic Flow

The application logic is split into the CLI layer (`cmd/`) and the Service layer (`cmd/services/`).

### 1. Command Execution (`cmd/root.go`)
The `rootRun` function orchestrates the entire process. It determines:
- Whether to create new CAs or renew leaf certs (via the `--renew` flag).
- Which directory structure to use (Default vs. Custom).
- Which CA names to use.

### 2. Service Layer (`cmd/services/`)
The services handle the heavy lifting by interacting with the filesystem and `openssl`.

*   **`rootCaService.go`**:
    *   Generates a 4096-bit RSA Root Key.
    *   Uses `openssl req -x509` to create the self-signed Root Certificate.
    *   Manages the `index.txt` and `serial` files required for CA operations.
*   **`intermediateCaService.go`**:
    *   Generates an Intermediate Key.
    *   Uses `openssl req` to create a Certificate Signing Request (CSR).
    *   Uses `openssl ca -batch` (signing via the Root CA) to produce the Intermediate Certificate.
*   **`appCrtService.go`**:
    *   Generates the Application Private Key.
    *   Creates the Leaf Certificate signed by the Intermediate CA.
    *   Produces a `fullchain.crt` containing the leaf + intermediate + root certificates.
    *   Optionally produces a `.pfx` (PKCS#12) file.

## 🛠 External Dependencies

The application relies on the host system having `openssl` installed and available in the `PATH`. `crtforge` uses Go's `os/exec` package to call `openssl` for CA-level operations (signing and CSR creation).

---
*Created for crtforge documentation.*
