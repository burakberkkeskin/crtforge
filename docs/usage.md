# 📖 Usage Guide: crtforge

This document provides detailed examples of how to use `crtforge` for various certificate generation scenarios.

## 🚀 Basic Usage (The "Quick Start")

To generate a full chain (Root $\rightarrow$ Intermediate $\rightarrow$ Leaf) with default settings:

```bash
crtforge myApp api.myapp.com
```

This creates a folder at `~/.config/crtforge/default/myApp/` containing:
- `fullchain.crt`
- `myApp.key`
- `myApp.crt`
- `myApp.csr`

---

## 🛠 Advanced Scenarios

### 1. Custom Names for CA Hierarchy
If you want to separate your production CA from your testing CA:

```bash
# Create a custom Root CA named 'CorporateRoot'
crtforge --root-ca CorporateRoot myApp api.myapp.com
```

### 2. Custom Intermediate CA
To create a specific intermediate CA for a specific department (e.g., 'DevOps'):

```bash
crtforge --root-ca CorporateRoot --intermediate-ca DevOps myApp api.myapp.com
```

### 3. Using the `--renew` Flag
If you already have a valid Root and Intermediate CA, and you only want to rotate the **leaf/application** certificate (e.g., because the old one expired):

```bash
# This will ONLY generate a new app certificate and key.
# It will NOT touch your Root or Intermediate CA files.
crtforge --renew myApp api.myapp.com
```

### 4. Generating PFX (PKCS#12) Files
If you need a `.pfx` file for Windows servers or certain Java applications:

```bash
crtforge myApp api.myapp.com --pfx
```
*Note: The default password for the PFX file is `changeit`.*

### 5. Trusting the Root CA Automatically
To automatically add your new Root CA to your system's trust store:

```bash
crtforge myApp api.myapp.com --trust
```

---

## 📂 Directory Structure Explained

By default, `crtforge` stores everything in `$HOME/.config/crtforge`.

```text
~/.config/crtforge/
├── default/
│   ├── rootCA/
│   │   ├── rootCA.crt      # The Root Certificate
│   │   ├── rootCA.key      # The Root Private Key
│   │   ├── rootCA.cnf      # Root CA Configuration
│   │   ├── index.txt       # CA database index
│   │   └── serial        # CA serial number file
│   └── myApp/              # Your application files
│       ├── fullchain.crt  # The complete chain
│       ├── myApp.crt      # The leaf certificate
│       ├── myApp.key       # The leaf private key
│       └── ...
```

---
*Created for crtforge documentation.*
