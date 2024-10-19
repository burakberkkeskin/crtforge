![image](https://github.com/safderun/crtforge/assets/58513283/59198e2d-abd3-4f29-bd4c-a0a3f160c8b8)

## 🔒 Overview

Crtforge is a cli tool which can generate a full chain self signed ssl certificate that includes root, intermediate, and application certificates.

👉🏻 You can act as your own local certificate authority for self-hosted home lab apps. Just create a series of application certs under the same root CA.

👉🏻 For development purposes, you can easily generate a large number of full-chain certificates.

## 📖 Table of Contents

- [🔒 Overview](#-overview)
- [📖 Table of Contents](#-table-of-contents)
- [Install Crtforge](#install-crtforge)
  - [Install Locally (Recommended)](#install-locally-recommended)
  - [Run With Docker](#run-with-docker)
  - [Building From Source](#building-from-source)
- [Quick Start](#quick-start)
- [Trusting Self Signed Root CA](#trusting-self-signed-root-ca)
- [Config File Structure](#config-file-structure)
- [Create Custom Root CA](#create-custom-root-ca)
- [Create Custom Intermediate CA](#create-custom-intermediate-ca)
    - [Under Default Root CA](#under-default-root-ca)
    - [Under Custom Root CA](#under-custom-root-ca)
- [Create PFX Certificate](#create-pfx-certificate)
- [Release a version](#release-a-version)

## Install Crtforge

### Install Locally (Recommended)

The binaries can be downloaded from the release page.

Simply execute the following commands to install crtforge on Linux and macOS:

```bash
sudo curl -L -o /usr/local/bin/crtforge "https://github.com/burakberkkeskin/crtForge/releases/latest/download/crtforge-$(uname -s)-$(uname -m)" && \
sudo chmod +x /usr/local/bin/crtforge
```

### Run With Docker

You don't need to install crtforge. You can create a alias and use crtforge almost like the same.

```bash
alias crtforge="docker run -it --rm -v "$HOME/.config":/root/.config safderun/crtforge:latest" && \
crtforge --version
```

You should see the version of the crtforge container.

### Building From Source

You can build the crtforge on your own machine.

To build, you should have go installed on your machine.

To build, run the commands below:

```bash
git clone https://github.com/safderun/crtforge.git && \
  cd crtforge && \
  version=$(git describe --tags --abbrev=0) && \
  commitId=$(git --no-pager log -1 --oneline | awk '{print $1}') && \
  go build -ldflags "-X crtforge/cmd.version=$version -X crtforge/cmd.commitId=$commitId" -o crtforge -v .
```

## Quick Start

📄 You can create the fullchain certificate within a second:

```bash
$ crtforge myApp api.myapp.com app.myapp.com

App certs created successfully.
App name: myApp
Domains: [api.myapp.com app.myapp.com]
To see your cert files, please check the dir: /home/ubuntu/.config/crtforge/default/myApp
```

⭐ You can also create a certificate with wildcard domain:

⚠️ Please place your domain between double quotes ("example.com") like the example below.

```bash
$ ./crtforge mySecondApp "*.example.com"

App certs created successfully.
App name: app8
Domains: [*.example.com]
To see your cert files, please check the dir: /home/ubuntu/.config/crtforge/testing/app8
```

🎉 Ta-Da Your certs are ready.

```bash
$ ls -l $HOME/.config/crtforge/default/myApp

total 24
-rw-rw-r-- 1 ubuntu ubuntu 5477 Aug 18 23:06 fullchain.crt
-rwxrwxr-x 1 ubuntu ubuntu  320 Aug 18 23:06 myApp.cnf
-rw-rw-r-- 1 ubuntu ubuntu 1395 Aug 18 23:06 myApp.crt
-rw-rw-r-- 1 ubuntu ubuntu  944 Aug 18 23:06 myApp.csr
-rw------- 1 ubuntu ubuntu 1704 Aug 18 23:06 myApp.key
```

You can use the `fullchain.crt` `myApp.key` in web servers like nginx, apache or mock servers.

## Trusting Self Signed Root CA

By default, if you create a web server with the fullchain cert, and make a http request, you will get self signed cert error.

To solve this, all you need to do is add a --trust or -t flag to crtforge.

For example:

```bash
# Create a app cert and trust the root cert of it
crtforge landingpage example.com --trust

# You can also use --trust flag with --root-ca flag for a custom root ca
crtforge -r medical backend api.example.com auth.example.com
```

> :information_source: Recommendation
> If you plan to use the app certs for long time for example on-prem home lab apps, create them with same root ca and trust only that root ca.
> So you don't need to trust all app certs one by one.

## Config File Structure

When you run the cli application without `--rootCa` flag, it creates a `default` in $HOME/.config/crtforge.

After that, rootCA and intermediateCA is created under that folder.

And last, your application's cert files are being created under the a folder named your app.

You can create multiple application certs under same rootCA.

## Create Custom Root CA

If you need a brand new chain, you can create a new rootCA with `--rootCa` flag.

For example:

```bash
crtforge --root-ca customRootCa myApp api.myapp.com app.myapp.com
```

After the command returns, a custom root ca named `customRootCa` has been created under `$HOME/.config/crtforge`.

The folder structure is same as default.

You can get the application certificates under `$HOME/.config/crtforge/customRootCa/myApp`

If you wwant custom application certificate directory, you can use `--output, -o` flag. 

For example:

```bash
crtforge --root-ca customRootCa --output /home/ubuntu myApp api.myapp.com app.myapp.com
```

## Create Custom Intermediate CA

#### Under Default Root CA

If you want to create a custom intermediate CA under the default root CA, you can use the --intermediate-ca or -i flag.

For example:

```bash
crtforge --intermediate-ca Backend apigateway apigw.myapp.com
crtforge -i Frontend website myapp.com app.myapp.com
```

This two commands will create two self signed cert under two intermediate ca which are under the default root ca.
The folder structure will be like below 👇

```
Root CA ("default")
  |
  |-- Intermediate CA 1 ("Backend")
  |      |
  |      |-- App 1 ("apigateway")
  |            |
  |            |-- apigw.myapp.com
  |
  |-- Intermediate CA 2 ("Frontend")
  |      |
  |      |-- App 2 ("website")
  |            |
  |            |-- myapp.com
  |            |-- app.myapp.com
```

#### Under Custom Root CA

You can also create multiple intermediate CAs under a custom root ca if you want.

All you need to do is combining custom root ca flag and custom intermediate ca flag.

Example:

```bash
crtforge --root-ca MedicalCompany --intermediate-ca Backend apigateway apigw.mymedicalcompany.com
crtforge -r MedicalCompany -i Frontend website mymedicalcompany.com app.mymedicalcompany.com

crtforge --root-ca FinanceCompany --intermediate-ca Backend apigateway apigw.myfinancecompany.com
crtforge -r FinanceCompany -i Frontend website myfinancecompany.com app.myfinancecompany.com
```

The cert structure will be same as above except the rootCA name.

```
Root CA ("MedicalCompany")
  |
  |-- Intermediate CA 1 ("Backend")
  |      |
  |      |-- App 1 ("apigateway")
  |            |
  |            |-- apigw.mymedicalcompany.com
  |
  |-- Intermediate CA 2 ("Frontend")
  |      |
  |      |-- App 2 ("website")
  |            |
  |            |-- mymedicalcompany.com
  |            |-- app.mymedicalcompany.com

  Root CA ("FinanceCompany")
  |
  |-- Intermediate CA 1 ("Backend")
  |      |
  |      |-- App 1 ("apigateway")
  |            |
  |            |-- apigw.myfinancecompany.com
  |
  |-- Intermediate CA 2 ("Frontend")
  |      |
  |      |-- App 2 ("website")
  |            |
  |            |-- myfinancecompany.com
  |            |-- app.myfinancecompany.com
```

## Create PFX Certificate

If you want to create certificate also in pfx format, you can add add --pfx or -p flag to your command.

The pfx password is hardcoded and it's "changeit".

- If you want to create a PFX certificate under default root CA:

```bash
crtforge gitlab gitlab.example.com --pfx
```

- If you want to create a PFX certificate under custom root and intermediate CA:

```bash
crtforge --root-ca git-providers --intermediate-ca engineer azure azure.example.com
```

## Release a version

- Define a version.

```bash
export crtforgeVersion=v1.4.0
```

- You should create a release branch from the master

```bash
git checkout master && git pull && \
git checkout -b release/${crtforgeVersion}
```

- Tag the commit

```bash
git tag --sign ${crtforgeVersion} -m "Added renew feature."
```

- Push the release branch and tags

```bash
git push && git push --tags
```
