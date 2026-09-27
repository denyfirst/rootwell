# ADR 0022: Separate explicit public-inventory upload from offline Workbench

The Workbench's browser-local inspection remains upload-free. Inventory is a
separate self-hosted page, protected by the existing loopback ready-session
gate. Its Save action explicitly sends only a bounded public DER certificate
or PEM bundle to the local daemon; the daemon independently parses and
validates it before an atomic encrypted-file replacement. The UI never sends
private key/PFX inputs by design, and the server refuses them even if a
client bypasses the picker. No external network service is used.

The session is tied to exact access-envelope bytes. On Linux, ready v2/v3
login derives the installation data key and keeps a copy in server memory for
the existing 12-hour session lifetime. Revocation/expiry drops the map entry
and best-effort clears its arrays; Go heap copies cannot be reliably erased.
Initial-password sessions receive no key. Legacy identity-less sessions can
still use Workbench but cannot open inventory. Native Windows inventory calls
remain unavailable until ACL and recovery semantics are reviewed.

POST requires exact same origin and a custom request header. GET requires the
header and refuses cross-site fetch metadata. JSON is size-bounded, rejects
unknown or duplicate fields, and never returns DER. The UI renders metadata
with text nodes, not HTML interpolation. Expiry is a browser-clock summary;
the API says verification was not performed. Import generation gives order;
the optional save time is a server-clock observation, not a tamper-evident
audit log. Backups remain manual after imports, and the
page warns accordingly. This is not a production or external-audit claim.
