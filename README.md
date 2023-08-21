## Overview

With no configuration, this utility generates a certificate chain that includes root, intermediate, and application certificates.

👉🏻 You can act as your own local certificate authority for self-hosted home lab apps. Simply create a number of app certs under the same root CA.

👉🏻 For development purposes, you can easily generate a large number of full-chain certificates.

## Install

The binaries can be downloaded from the release page.

Simply execute the following commands to install crtforge:

```bash
sudo curl -L -o /usr/bin/crtforge https://github.com/safderun/crtForge/releases/download/v1.2.0/crtforge-$(uname -s)-$(uname -m) && \
sudo chmod +x /usr/bin/crtforge
```

## Quick Start

- You can create the fullchain cert within a second:

```bash
crtforge myApp api.myapp.com app.myapp.com
```

- Your certs will be in the config file of crtforge

```bash
cd $HOME/.config/crtforge/default/myApp && \
ls -l
```

- 🎉 Ta-Da Your certs are ready.
- To output should be like below:

```output
ls -l
total 24
-rw-rw-r-- 1 ubuntu ubuntu 5477 Aug 18 23:06 fullchain.crt
-rwxrwxr-x 1 ubuntu ubuntu  320 Aug 18 23:06 myApp.cnf
-rw-rw-r-- 1 ubuntu ubuntu 1395 Aug 18 23:06 myApp.crt
-rw-rw-r-- 1 ubuntu ubuntu  944 Aug 18 23:06 myApp.csr
-rw------- 1 ubuntu ubuntu 1704 Aug 18 23:06 myApp.key
```

> :information_source: Files and Meanings
>
> You will probably use `fullchain.crt` `myApp.crt` `myApp.key`
>
> File named `fullchain.crt` contains myApp.crt, intermediateCa.crt and rootCa.crt
>
> File named `myApp.crt` contains the public ssl cert.
>
> File named `myApp.key` contains the private ssl key. Keep it secret!

> :information_source: Usage
>
> You can use the `fullchain.crt` `myApp.key` in web servers like nginx, apache or mock servers.

## Background

When you run the cli application without `--rootCa` flag, it creates a `default` in $HOME/.config/crtforge.

After that, rootCA and intermediateCA is created under that folder.

And last, your application's cert files are being created under the a folder named your app.

You can create multiple application certs under same rootCA.

## Custom Root CA

If you need a brand new chain, you can create a new rootCA with `--rootCa` flag.

For example:

```bash
crtforge --root-ca customRootCa myApp api.myapp.com app.myapp.com
```

After the command returns, a custom root ca named `customRootCa` has been created under `$HOME/.config/crtforge`.

The folder structure is same as default.

You can get the application certificates under `$HOME/.config/crtforge/customRootCa/myApp`

## Custom Intermediate CA

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
