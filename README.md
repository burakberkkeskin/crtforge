## Overview

This tool is for creating cert chain that has root, intermediate and application with zero config.

You can easily create multiple fullchain certs for multiple applications.

## Install

You can download the binaries from the release page.

To install, simple run the commands below:

```bash
sudo curl -L -o /usr/bin/crtforge https://github.com/safderun/crtForge/releases/download/v1.0.0/crtforge-$(uname -s)-$(uname -m) && \
sudo chmod +x /usr/bin/crtforge
```

## Quick Start

- You can create the fullchain cert within a second:

```bash
sslforge myApp api.myapp.com app.myapp.com
```

- Your certs will be in the config file of sslforge

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

> :information_source: Files and meanings
> You will probably use `fullchain.crt` `myApp.crt` `myApp.key`
>
> File named `fullchain.crt` contains myApp.crt, intermediateCa.crt and rootCa.crt
>
> File named `myApp.crt` contains the public ssl cert.
>
> File named `myApp.key` contains the private ssl key. Keep it secret!

> :information_source: Usage
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
sslforge --rootCa customRootCa myApp api.myapp.com app.myapp.com
```

After the command returns, a custom root ca named `customRootCa` has been created under `$HOME/.config/crtforge`.

The folder structure is same as default.

You can get the application certificates under `$HOME/.config/crtforge/customRootCa/myApp`
