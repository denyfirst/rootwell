# Rootwell, by denyfirst

Rootwell is a self-hosted place for TLS certificates and their private keys.
It keeps them encrypted, will renew them without anyone signing in, and checks
what a website really serves. Its offline tools open and convert certificate,
key and PFX files without uploading them anywhere.

> Your private root of trust.

**Status:** in development, not released. Use only test material. What works
today is in [`docs/STATUS.md`](docs/STATUS.md). Where it is going is in
[`docs/PRODUCT-PLAN.md`](docs/PRODUCT-PLAN.md).

Rootwell is one of three separate Denyfirst products:

- **Porch** measures what a server presents from the outside.
- **Keybash** keeps SSH and RDP access.
- **Rootwell** keeps certificates and keys.

## Principles

- Security first, then correctness, privacy, recoverability, comfort and
  features.
- A feature is done when its success, refusal, malformed-input and abuse
  cases are tested, and each test fails when the feature is deliberately
  broken.
- Private material is never sent to Denyfirst and never committed.
- No home-made cryptography.
- Risky actions are explicit, recoverable and fail closed.

## Try the tools

The `rootwell` command works offline on Windows, macOS and Linux:

```text
go build ./cmd/rootwell
rootwell inspect certificate.pem
rootwell explore bundle.pem
rootwell convert --input certificate.cer --to pem --output certificate.pem
rootwell match --cert certificate.pem --key private-key.pem
rootwell verify server.pem --trust-bundle roots.pem --intermediates intermediates.pem --hostname portal.example.com
```

On Linux it also handles PFX files and private keys. Passwords are always
asked on the terminal, and existing files are never overwritten.

```text
rootwell pfx-create --cert server.crt --key server-key.pem --chain intermediates.pem --output ./private/server.p12
rootwell pfx-inspect --input ./private/server.p12
rootwell pfx-extract-cert --input ./private/server.p12 --sha256 AA:BB:... --to pem --output server.pem
rootwell pfx-extract-key --input ./private/server.p12 --sha256 AA:BB:... --output ./private/server-key.pem
```

`rootwell-probe` is built separately. It checks one live TLS endpoint, at an
IP and port you name, against a root you pin:

```text
rootwell-probe --hostname portal.example.com --connect-ip 192.0.2.10 --port 443 \
  --trust-bundle roots.pem --root-sha256 <fingerprint> --expected-leaf server.crt
```

The contracts for these commands:

- [inspect JSON](docs/INSPECT-JSON.md)
- [match](docs/MATCH.md)
- [verify](docs/VERIFY-TLS.md)
- [formats](docs/FORMAT-MATRIX.md)

## Run the web service for development

`rootwelld` runs on Linux, or in its container. `init` and `serve` take a
data directory and an instance key file, which must sit outside the data
directory.

```sh
GOOS=js GOARCH=wasm go build -trimpath -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/workbench/wasm_exec.js
install -d -m 0700 "$HOME/rootwell-key"
go run ./cmd/rootwelld init "$HOME/rootwell-data" "$HOME/rootwell-key/instance.key"
go run ./cmd/rootwelld serve "$HOME/rootwell-data" "$HOME/rootwell-key/instance.key" web/workbench
```

1. `init` shows the instance key's recovery code. Type `SAVED` once you have
   kept it. Keep the code away from the host and from backups: losing both the
   key file and the code loses every saved certificate and key. `init` then
   prints a setup code, which works once, for 24 hours.
2. Open `http://localhost:4180/setup` on the same machine. Enter the setup
   code, a name and a password, add Rootwell to an authenticator app on your
   phone, and save the ten recovery codes.
3. From then on, sign in with the name, the password and a code from the
   phone.

The menu has six pages: **Certificates** (the home page), **Website check**,
**Inspect**, **Convert**, **Request** and **Account**. Inspect, Convert and
Request work on files only inside the browser
([the pages](web/workbench/README.md)).

The service listens on this host's loopback addresses only, over plain HTTP
until HTTPS arrives. A lost phone or password, a lost key file and backups are
covered in [recovery](docs/RECOVERY.md): until online backups arrive, a backup
is a copy of the data directory made with the service stopped, and the key
file never goes with it. A Docker profile is in
[container recovery](docs/CONTAINER-RECOVERY.md). HTTPS is next; Phase 3b then
brings backups from the web, and an install script follows later.

## Documents

- [Engineering workflow](docs/ENGINEERING.md)
- [Security invariants](docs/SECURITY-INVARIANTS.md)
- Threat models:
  - [the pages](docs/THREAT-MODEL.md)
  - [custody](docs/CERTIFICATE-CUSTODY-THREAT-MODEL.md)
  - [ACME](docs/ACME-THREAT-MODEL.md)
  - [website check](docs/WEBSITE-CHECK-THREAT-MODEL.md)
- [Architecture decisions](docs/adr/)
- [Security policy](SECURITY.md)

## Licence

AGPL-3.0, as Porch and Keybash. See [`LICENSE`](LICENSE). The Schibsted
Grotesk typeface the pages use is under the SIL Open Font License 1.1.
