# ADR 0052: Interactive maintenance has no Docker log retention

Status: accepted for the Linux development Compose configuration.

`rootwelld init` prints a random setup password only to an interactive local
terminal. Recovery enrollment similarly shows an offline recovery code.
Requiring TTY does not stop Docker's default logging driver from collecting
stdout/stderr. A daemon that never logs credentials is therefore insufficient
to protect maintenance output from Docker log retention.

The separate, network-disabled maintenance service sets `logging.driver: none`.
Serving retains normal secret-free diagnostics. No host logging settings or
operator containers are changed. The normalized Compose guard requires the
exact maintenance driver and no logging options. Unit tests reject missing,
malformed and capturing configurations and accept the valid restricted service.
The disposable Linux drill checks the actual container's LogConfig and proves
that harmless attached usage output is not recoverable through `docker logs`.
It does not generate or capture a real setup password for this test.

Operators using `docker run` instead of this Compose configuration must select
`--log-driver none` themselves. The change does not erase old logs or reconfigure
existing containers. Terminal recording, host compromise, privileged observers,
custom Compose overrides and copies of previously emitted credentials remain
outside this guarantee. Potentially retained credentials must be rotated and
old log copies handled by their operator. No production audit is claimed.

References: [Docker logging configuration](https://docs.docker.com/engine/logging/configure/)
and [Compose logging](https://docs.docker.com/reference/compose-file/services/#logging).
