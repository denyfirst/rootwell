# ADR 0013: Mandatory first-login password rotation

Status: accepted. Loopback development gateway integration implemented;
production server integration pending.

Each self-hosted installation will receive a distinct randomly generated
initial password. It is a setup credential, not a normal operator credential.
The authenticated key envelope starts in `change-required`; a normal data-key
open refuses that state. A successful change to a distinct password atomically
rewraps the unchanged data key and enters `ready`. Leaving setup unfinished
does not silently activate the installation; the same setup credential may be
used later to attempt the required change.

Porch's current first-start password appears on daemon stderr and may persist
in Docker logs. Rootwell's product invariant forbids password material in
logs. Its `rootwelld init` workflow is interactive on the local host, and the
runtime does not redisplay or recover the initial password. The loopback web
gate issues a setup-only session until rotation succeeds, then invalidates
all sessions and requires a fresh normal sign-in. Production remote access and
secret custody remain outside this ADR.

See [the threat model](../INSTANCE-ACCESS-THREAT-MODEL.md) for residual risks
and deployment blockers.
