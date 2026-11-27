# Rootwell pages

This directory holds the pages `rootwelld` serves after sign-in, their scripts,
the browser workers and the one stylesheet every page uses. The pages are
plain HTML and JavaScript with no dependencies. The browser engine is the Go
core compiled to WebAssembly (`rootwell.wasm`), built from the same code as
the `rootwell` command.

## The pages

The menu has eight pages. `/` leads to Certificates.

| Page | Route | Files | What it does |
|---|---|---|---|
| Certificates | `/certificates` | `certificates.html`, `certificates.js`, and `certificate-pfx.js` with `certificate-pfx-worker.js` from `cmd/rootwelld/auth` | Lists the saved certificates with the days each has left, where it is used and whether its key is kept; opens one in a side sheet; adds certificates, bundles, keys and PFX files; renews one, lists the requests waiting for their certificate, and shows what was replaced |
| Website check | `/website-check` | `website-check.html`, `website-check.js` in `cmd/rootwelld/auth` | Asks this server to read what an HTTPS website or internal server sends, explains the chain, and watches chosen sites once a day through `/api/watch` |
| Inspect | `/inspect` | `inspect.html`, `inspect.js` | Shows who a certificate is for, who issued it, how long it lasts, whether its chain is complete, and whether a private key belongs to it |
| Convert | `/convert` | `convert.html`, `convert.js` | Turns a certificate, key or PFX into the format a server needs |
| Request | `/request` | `request.html`, `request.js`, `request-keep.js` | Makes a CSR: a new key is made and kept by Rootwell, an existing one stays in the browser |
| Alerts | `/alerts` | `alerts.html`, `alerts.js`, and `fresh.js` | Saves where alerts go, Telegram and e-mail, sends a test, and lists what was sent |
| Account | `/account` | `account.html`, `auth.js`, `qr.js` and `passkey.js` in `cmd/rootwelld/auth`, and `fresh.js` | Changes the password, moves to a new phone, makes new recovery codes, adds and removes passkeys, and says how to get back in from the server |
| Installation | `/installation` | `installation.html`, `auth.js` (its installation mode) and `passkey.js` in `cmd/rootwelld/auth`, and `fresh.js` | Shows the names Rootwell answers to on port 4180, its certificate authority's fingerprint with a link to `/rootwell-ca.pem`, when the server certificate ends and how many certificates are saved; downloads a backup; says what `restore`, `key-rotate` and `key-export` do on the server |

Every change on Certificates names the list's change count the page last
read, and the server refuses an out-of-date one. After a save, the page takes
the new count from the save's answer and says Saved at once; a list read
already under way is waited for, not reused, so an add made right after a
save is not refused as out of date.

Sign-in (`/login`) and setup (`/setup`) also come from `cmd/rootwelld/auth`.
Sign-in takes the name and password, then a code from the phone or a
recovery code; when the account has a passkey and the browser can use one,
it also offers **Use a passkey instead**. Setup takes a setup code from the
server, a name and a password, shows a QR code for an authenticator app, and
then the ten recovery codes, once. The sign-in page also links Rootwell's
certificate authority, `/rootwell-ca.pem`, for a browser that warned about
the page.

Every page links `/rootwell.css`, loads `/theme.js` for the colour scheme and
`/session.js` for Sign out, and carries no inline style or script. The
stylesheet, `theme.js`, `favicon.svg`, the typeface and the sign-in scripts
(`auth.js`, `qr.js`, `passkey.js`) are served before sign-in so that the
sign-in and setup pages work and look like the rest, and so is
`/rootwell-ca.pem`; everything else needs a signed-in session.

The hidden Renewals page and its older stylesheet were removed on
23 November 2026; a new Renewals page comes with real renewal in Phase 3c.

## Shared files

- `rootwell.css` — the graphite design: tokens for light and dark, fixed
  sizes, the rail, cards, pills, the lifetime bar and the chain.
- `ui.js` — helpers every page uses: elements built with `textContent`,
  icons, status pills, the lifetime bar, the chain order, drop zones, a ZIP
  writer and a password maker.
- `theme.js` — the colour scheme switch; it remembers only that choice.
- `session.js` — Sign out; it talks only to `/api/session`.
- `fresh.js` — the dialog that asks for a code from the phone when Rootwell
  answers 428; it sends the code to `/api/fresh`. When the browser can use
  passkeys, its **Use a passkey** button answers instead, through
  `/api/passkey/options` and `/api/passkey`. Certificates, Account and
  Installation load it.
- `passkey.js`, from `cmd/rootwelld/auth` — turns Rootwell's passkey options
  into the browser's WebAuthn request, always asking the device to verify
  the person, and returns the answer as the fields the server reads. It
  asks for no attestation and keeps nothing. Sign-in, Certificates, Account
  and Installation load it.
- `wasm-loader.js` — fetches `rootwell.wasm` from this server, without
  credentials or redirects, and hands the engine to the page.
- `private-worker-client.js` and `private-key-worker.js`,
  `pfx-worker-client.js` and `pfx-worker.js`, `csr-worker-client.js` and
  `csr-worker.js` — one-shot workers for private keys, PFX files, requests
  and key matching.

## Security boundary

- Inspect, Convert and Request read the files a person chooses and make no
  request: their scripts and `ui.js` have no network, storage, worker or
  HTML-writing capability of their own. Files never leave the browser.
  Request's new keys are made by Rootwell itself: `request-keep.js` sends the
  names and details a person typed to `/api/requests/create`, after
  `/api/inventory` for the list's count, and reads no file (ADR 0091).
- Certificates sends what a person adds only to this Rootwell's own
  `/api/inventory`, `/api/certificates` and `/api/requests` endpoints, with the
  `X-Rootwell-Request` header and same-origin credentials. A PFX is opened in
  its worker first; the server receives its certificate and the key encrypted
  again for the transfer, never the PFX itself or its password.
- Alerts reads and changes only `/api/alerts`. A saved mail password or bot
  token never comes back to the page: leaving its field empty keeps it.
  Saving or turning off a channel needs a fresh code (ADR 0092).
- No page asks for the Rootwell password again; only changing it on Account
  takes the current one. Downloading a key, deleting a certificate that has
  one, changing the password, the phone or the recovery codes, adding or
  removing a passkey, and downloading a backup need a code from the phone, a
  recovery code or a passkey in the last ten minutes. Without one the server
  answers 428 and does nothing; the page calls `rootwellFresh()` from
  `fresh.js`, which asks for the code in a dialog, and sends the same request
  once more. Cancel leaves everything as it was.
- Installation reads `/api/installation`, which changes nothing, and asks for
  a backup with a POST to `/api/backup`. The backup is a file, not JSON:
  `auth.js` fetches it and hands it to the browser as a download, under the
  name the server gives. It is the whole vault, sealed, without the instance
  key. A vault over 64 MiB gets 507, and the page says to copy it on the
  server with Rootwell stopped.
- A passkey works only on the name the page was opened on, such as
  `localhost` or a LAN name, never on an IP address; there the pages say so
  and the server refuses.
- Private keys, PFX files and requests are handled in a fresh worker for each
  operation, with a deadline, cancellation when the page moves on, and
  clearing of the bytes it was given. The server sends each worker script
  with its own policy: no network and no further workers.
- Every page is served with a strict Content Security Policy: scripts,
  styles, images, fonts and connections only from this server,
  `'wasm-unsafe-eval'` for the engine, and nothing inline.
- Text from certificates, files and the server is always written with
  `textContent`.
- Inspect forgets the certificate and any typed password when the page is
  hidden or left. Convert and Request forget files, keys and passwords when
  the page is left, when other files are chosen and after ten idle minutes.
  Byte buffers are cleared on a best-effort basis; browser memory, password
  strings, extensions and a compromised host cannot be fully controlled.

## Build the engine

`rootwell.wasm` and `wasm_exec.js` are not committed. They must come from the
exact Go version `go.mod` names.

PowerShell:

```powershell
$env:GOOS = "js"
$env:GOARCH = "wasm"
go build -trimpath -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
Remove-Item Env:GOOS, Env:GOARCH
Copy-Item -Force (Join-Path (go env GOROOT) "lib/wasm/wasm_exec.js") web/workbench/wasm_exec.js
```

POSIX shell:

```sh
GOOS=js GOARCH=wasm go build -trimpath \
  -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/workbench/wasm_exec.js
```

Then serve this directory with
`rootwelld serve <data-dir> <instance-key-file> web/workbench`, and open
`https://localhost:4180`. The daemon refuses to start when a page file or the
engine is missing.

## Tests

The page tests drive each page with the real engine and generated,
non-production material from `scripts/generate-convert-fixture.go`; no
sample file ships with the pages.

```sh
wasm=path/to/rootwell.wasm
runtime="$(go env GOROOT)/lib/wasm/wasm_exec.js"
node scripts/test-certificates.mjs "$wasm" "$runtime"
node scripts/test-inspect.mjs "$wasm" "$runtime"
node scripts/test-convert.mjs "$wasm" "$runtime"
node scripts/test-request.mjs "$wasm" "$runtime"
node scripts/test-website-check.mjs
node scripts/test-session.mjs
node scripts/test-rootwelld-auth.mjs
```

`test-rootwelld-auth.mjs` drives the sign-in, setup, Account and
Installation pages and the fresh-code dialog, including a passkey at sign-in,
one added and removed on Account, and a backup that asks for a fresh code
once and arrives as a download.

`internal/uicontract` checks the design tokens, contrast, the shared rail,
one stylesheet (`rootwell.css`) for every page and the capability boundaries
above;
`cmd/rootwelld` checks what each route serves, to whom, and under which policy.
