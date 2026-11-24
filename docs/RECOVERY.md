# Rootwell recovery on Linux

**Status:** development design.

- What opens an installation:
  - the **instance key file** opens the vault, `rootwell.db`, which holds the
    certificates, their keys and the account. Its **recovery code** rebuilds
    the key file;
  - a person signs in with a **name and password**, then a **code from the
    phone**. Each of ten **recovery codes** stands in for the phone once, and
    a **passkey**, if you add one, stands in for it every time;
  - a **setup code**, made on the server, sets up the account, or replaces a
    lost password or phone.
- Browsers reach Rootwell over HTTPS once they trust its own **certificate
  authority**, which it keeps in the vault.
- A **backup** is downloaded from the **Installation** page while Rootwell
  runs. Restoring one, moving to a new instance key and showing the key's
  recovery code again are done on the server, with the service stopped.
- `rootwelld` runs only on Linux, or in its container.

Codes are never accepted as command arguments or environment variables:
`key-restore`, and `restore` without a key file, ask for the recovery code on
the local terminal, and `init`, `setup-code`, `key-rotate` and `key-export`
print their codes there. Keep codes out of shell history, chat, tickets and
logs, and protect the terminal's scrollback.

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

## Passkeys

A passkey lets a device, such as the computer you sign in from or a security
key, stand in for the phone code. The device asks for your fingerprint, your
face or its PIN, and the passkey cannot be used on a site that only looks
like Rootwell. It is optional. The phone stays, and it is the way back when
a passkey is lost.

- **Add one** on the **Account** page: type a name you will recognise, such
  as `Work laptop`, choose **Add a passkey** and follow the browser. It asks
  for a code from the phone first, unless you entered one in the last ten
  minutes. An account keeps up to ten passkeys.
- **Sign in** with the name and password, then choose **Use a passkey
  instead**. When Rootwell asks for a code before a change, such as a key
  download, its dialog offers **Use a passkey** too.
- **One name only.** A passkey works only on the name it was added on: one
  added on `https://localhost:4180` does not work on
  `https://rootwell.lan:4180`. Add one on each name you use. Browsers allow
  no passkeys on an IP address such as `192.168.1.5`; use a DNS name for the
  LAN.
- Adding or removing a passkey signs out every other browser.

## Lost phone

Sign in with a recovery code in place of the phone code; each one works once.
Then, on the **Account** page:

- **Move to a new phone** adds Rootwell to the new phone. The old phone's
  codes stop working.
- **Make new codes** replaces the recovery codes, if few are left. The old
  ones stop working.

Either one signs out every other browser.

## Lost passkey device

Sign in with a code from the phone, or a recovery code, as before. Then, on
the **Account** page, **Remove** the lost device's passkey; that signs out
every other browser. Until then, whoever holds the device still needs your
password and the device's fingerprint, face or PIN.

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
- This replaces the password, the phone and the recovery codes, removes
  every passkey, since the device that holds one may be lost too, and signs
  out every other browser. Certificates are not touched. Add passkeys again
  afterwards if you want them.
- The code works once, for 24 hours, and only for that name. A newer code
  replaces it.
- Without a name, `setup-code` makes a code for the first account; once an
  account exists, it refuses.

Anyone who can run `rootwelld` as the service user can do this. It is the way
back from the server itself.

## Backup

On the **Installation** page, in the menu under Account, choose **Download a
backup**. Rootwell asks for a code from the phone, a recovery code or a
passkey, unless you entered one in the last ten minutes, and the browser
saves `rootwell-backup-<date and time>.db`. Rootwell keeps running.

- A backup is a copy of the whole vault, made in one step while Rootwell
  works, so it is consistent. It holds every certificate and key, the
  account, its passkeys and Rootwell's certificate authority, all sealed.
- It holds no instance key: it opens only with the key Rootwell had when the
  backup was made, or that key's recovery code. Store backups somewhere
  safe, apart from the code.
- Make a new backup after changes you want to keep. Rootwell makes no
  automatic backups.

The page hands out up to 64 MiB. For a larger vault, or without a browser,
copy the vault file on the server with the service stopped; a copy made while
it runs may be incomplete:

```text
# stop rootwelld serve first
cp -a /private/rootwell-data/rootwell.db /private/backup/rootwell-backup-2026-11-24.db
```

**Never copy the key file to the backup location.** The recovery code, kept
apart, is the key's backup.

## Restore

`restore` puts a backup into a new, empty data directory, **never the live
one**. Stop the service first, then start it on the restored directory:

```text
# stop rootwelld serve first
rootwelld restore /private/backup/rootwell-backup-20261124T120000Z.db /private/rootwell-data-restored /private/rootwell-key/instance.key
rootwelld serve /private/rootwell-data-restored /private/rootwell-key/instance.key web/workbench
```

- It makes the directory, `0700`, if it is missing, and refuses one that is
  not empty. Keep the old directory until the restored Rootwell works.
- It keeps the backup only if it opens with the key; otherwise it leaves
  nothing in the directory. A backup opens only with the key the vault had
  when it was made: after a [key rotation](#move-to-a-new-instance-key), an
  older backup needs the old key, or its old recovery code.
- **If the key file is lost too,** name a key file that does not exist yet,
  in a `0700` directory (`install -d -m 0700 /private/rootwell-key`).
  `restore` asks for the instance key's recovery code, and writes the key
  file from it once the backup opens with it.
- A copy made on the server restores the same way: give its `rootwell.db`.
- The account comes back as it was when the backup was made: sign in again,
  with the password and phone of that time. If those are lost, make a setup
  code with the account's name. Its passkeys come back as they were too: on
  the Account page, remove again any you removed since the backup.
- The certificate authority and its names come back as they were too. If the
  names changed after the backup was made, trust that older authority again,
  or run `serving-names` to make a new one.
- An older backup brings back certificates deleted since; Rootwell does not
  detect that.

## Move to a new instance key

Move to a new instance key when the key file or its recovery code may have
been seen or copied:

```text
# stop rootwelld serve first
rootwelld key-rotate /private/rootwell-data /private/rootwell-key/instance.key
```

- It shows the new key's recovery code once. Type `SAVED` once it is kept;
  until then nothing changes.
- It then moves the vault to the new key in one step, rewrites the vault's
  file so nothing left in it opens with the old key, and puts the new key
  file in place of the old one. From then on only the new key, or its new
  code, opens Rootwell. If rewriting the file fails, it says so: run
  `key-rotate` once more. Everything in the vault stays as it was: accounts,
  passkeys, certificates, and the recovery and setup codes not yet used.
- **Backups made before keep opening with the old key and its old recovery
  code only.** Keep the old code as long as you keep those backups, and make
  a new backup after rotating. A rotation cannot reach a copy already taken:
  whoever holds one with the old code can still open it.
- If it is interrupted, it leaves `instance.key.new` beside the key file, and
  the next `key-rotate` refuses and says what to do. If `serve` does not
  start with `instance.key`, the vault moved already: rename
  `instance.key.new` to `instance.key`. Otherwise remove `instance.key.new`
  and rotate again.

## Show the recovery code again

`key-export` prints the recovery code of the key in the key file, once it has
checked that the key opens the vault. Use it when the written code is lost
but the key file is not, or to check the copy you kept:

```text
# stop rootwelld serve first
rootwelld key-export /private/rootwell-data /private/rootwell-key/instance.key
```

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
