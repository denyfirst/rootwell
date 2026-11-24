# Rootwell recovery on Linux

**Status:** development design.

- What opens an installation:
  - the **instance key file** opens the vault, `rootwell.db`, which holds the
    certificates, their keys and the account. Its **recovery code** rebuilds
    the key file;
  - a person signs in with a **name and password**, then a **code from the
    phone**. Each of ten **recovery codes** stands in for the phone once;
  - a **setup code**, made on the server, sets up the account, or replaces a
    lost password or phone.
- Browsers reach Rootwell over HTTPS once they trust its own **certificate
  authority**, which it keeps in the vault.
- Phase 3b of `PRODUCT-PLAN.md` adds backups and restores started from the
  Installation page, and key rotation. Until then, this page is the procedure.
- `rootwelld` runs only on Linux, or in its container.

Codes are never accepted as command arguments or environment variables:
`key-restore` asks for the recovery code on the local terminal, and `init` and
`setup-code` print their codes there. Keep codes out of shell history, chat,
tickets and logs, and protect the terminal's scrollback.

## Setup

The key file lives in its own private directory, **outside** the data
directory, so a copy of the data never carries its key. `init` and `serve`
refuse a key file inside the data directory.

```text
install -d -m 0700 /private/rootwell-key
rootwelld init /private/rootwell-data /private/rootwell-key/instance.key
```

`init` shows two things:

1. the **instance key's recovery code**: `RW1-` and groups of letters and
   digits. Type `SAVED` once it is kept. Only then does `init` write the key
   file (`0600`) and create the vault. It never replaces an existing key file
   or installation.
2. a **setup code** for the first account. It works once, for 24 hours.

Keep the recovery code offline, apart from this host and from every backup. It
is the key file's only backup. **Losing both the key file and the code loses
every saved certificate and key.**

Then start the service:

```text
rootwelld serve /private/rootwell-data /private/rootwell-key/instance.key web/workbench
```

On its first start, `serve` makes Rootwell's own certificate authority. At
every start it prints where it answers and the authority's SHA-256
fingerprint. An installation from before HTTPS keeps its accounts and
certificates, and gets its authority at its next start. Trust the authority
in your browser first ([below](#trust-rootwells-certificate-authority)), then
open `https://localhost:4180/setup` on the same host:

1. Enter the setup code, a name, and a password of at least 15 characters,
   twice.
2. Scan the QR code with an authenticator app on your phone, or type the key
   shown under it. Enter the six-digit code the app shows. Only now is the
   account saved.
3. Copy or download the ten recovery codes, and keep them apart from the
   phone. They are shown only this once.

You are then signed in. Each later sign-in takes the name, the password and a
code from the phone.

If the setup code runs out first, stop the service and make a new one:

```text
rootwelld setup-code /private/rootwell-data /private/rootwell-key/instance.key
```

## Trust Rootwell's certificate authority

Rootwell speaks only HTTPS, with TLS 1.3, on port 4180. Its certificate comes
from its own authority, which no browser knows until you trust it. Do this
once on each computer you use Rootwell from:

1. Open `https://localhost:4180` (or the name you added). The browser warns
   that it does not know the certificate; this first time, that is expected.
   Continue, but do not sign in yet.
2. Download the authority with the link on the sign-in page,
   `/rootwell-ca.pem`.
3. Check that its SHA-256 fingerprint is the one `rootwelld` printed, every
   pair of characters, for example on the host with
   `openssl x509 -in rootwell-ca.pem -noout -fingerprint -sha256`. If they
   differ, stop: something else answered. A file you checked can be copied
   to your other computers.
4. Trust the file as an authority that identifies websites, in the browser's
   certificate settings or in the operating system's trusted root
   certificates. Reload: the warning is gone.

The authority lasts ten years and can sign only for this installation's
names. It publishes no revocation list, so on Windows `curl` and other
command-line tools that use the system's TLS (schannel) need
`--ssl-no-revoke` for Rootwell; browsers do not.

## Reach Rootwell from another machine

By default Rootwell answers only on this host: `localhost`, `127.0.0.1` and
`::1`. To reach it over the LAN or a VPN, give it the names people will type,
then the address to listen on. `192.168.1.5` and `rootwell.lan` are examples:

```text
# stop rootwelld serve first
rootwelld serving-names /private/rootwell-data /private/rootwell-key/instance.key 192.168.1.5 rootwell.lan
rootwelld serve /private/rootwell-data /private/rootwell-key/instance.key web/workbench --listen 192.168.1.5
```

- `serving-names` takes DNS names and IP addresses, no wildcards, at most 16
  names with the three loopback ones included. It replaces the names given
  before; with none, Rootwell goes back to this host only.
- **Every change of names makes a new authority**, since an authority's names
  are fixed. `serving-names` prints its fingerprint. Trust the new one on
  every computer, as above, and remove the old one.
- `--listen` takes an IP address of this host that the names cover; repeat it
  for another. Loopback is always there; `0.0.0.0`, `::`, a multicast
  address and an address not covered are refused. Rootwell never listens on
  every address.
- A DNS name must lead to that address: through your DNS, or each computer's
  hosts file.
- Open `https://192.168.1.5:4180` or `https://rootwell.lan:4180`. On these
  names the browser also remembers to use only HTTPS, for a year.
- Do not expose Rootwell to the internet.

## Lost phone

Sign in with a recovery code in place of the phone code; each one works once.
Then, on the **Account** page:

- **Move to a new phone** adds Rootwell to the new phone. The old phone's
  codes stop working.
- **Make new codes** replaces the recovery codes, if few are left. The old
  ones stop working.

Either one signs out every other browser.

## Lost password, or lost phone and recovery codes

Make a setup code for the account, with the service stopped. Give the
account's name; `ada` is an example:

```text
# stop rootwelld serve first
rootwelld setup-code /private/rootwell-data /private/rootwell-key/instance.key ada
```

- Start the service, open `/setup`, and enter the code with the same name and
  a new password. Then add the phone and save the new recovery codes, as at
  the first setup.
- This replaces the password, the phone and the recovery codes, and signs out
  every other browser. Certificates are not touched.
- The code works once, for 24 hours, and only for that name. A newer code
  replaces it.
- Without a name, `setup-code` makes a code for the first account; once an
  account exists, it refuses.

Anyone who can run `rootwelld` as the service user can do this. It is the way
back from the server itself.

## Backup

Online backup comes in Phase 3b. Until then, copy the data directory with the
service stopped:

```text
# stop rootwelld serve first
cp -a /private/rootwell-data /private/backup/rootwell-data-2026-11-24
```

- The copy holds `rootwell.db`: the certificates, their keys and the account,
  all sealed. Without the key file or the recovery code it opens nothing.
- **Never copy the key file to the backup location.** The recovery code, kept
  apart, is the key's backup.
- Copy while the service runs and the copy may be incomplete: stop it first.
- Make a new copy after changes you want to keep, under a new name. Rootwell
  makes no automatic backups.

## Restore

Restore into a new, empty `0700` directory, **never the live one**:

```text
install -d -m 0700 /private/rootwell-data-restored
cp -a /private/backup/rootwell-data-2026-11-24/. /private/rootwell-data-restored/
```

- `rootwell.db` must stay `0600` and owned by the service user; `cp -a` keeps
  that. The vault refuses a directory or file that others can read.
- If the key file still exists, start `serve` with the restored directory and
  the same key file.
- If the key file is lost too, rebuild it, then start `serve`:

  ```text
  install -d -m 0700 /private/rootwell-key
  rootwelld key-restore /private/rootwell-data-restored /private/rootwell-key/instance.key
  ```

- The account comes back as it was when the copy was made: sign in with the
  password and phone of that time. If those are lost, make a setup code with
  the account's name.
- The certificate authority and its names come back as they were too. If the
  names changed after the copy was made, trust that older authority again,
  or run `serving-names` to make a new one.
- An older copy brings back certificates deleted since; Rootwell does not
  detect that.

## Lost key file

`key-restore` rebuilds a lost key file from the recovery code:

```text
rootwelld key-restore /private/rootwell-data /private/rootwell-key/instance.key
```

- Stop the service first: it holds the vault, and `key-restore` refuses while
  it runs.
- It asks for the code on the terminal, and checks that the code opens the
  vault in that data directory before writing anything. A code from another
  installation is refused.
- It never replaces an existing key file. The key directory must be `0700`.

After a failed command, do not repeat it blindly: first look at the
directory.

The Docker procedure is in [`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md).
