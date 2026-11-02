# Security Policy

## Supported versions

Until 1.0.0 is released, only the latest commit on the default branch and the
latest release receive security fixes.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting:
<https://github.com/bhager42/teslachargingmonitor/security/advisories/new>

Include affected version/commit, a description, reproduction steps and impact.
You can expect an acknowledgement within 7 days and a fix or mitigation plan
within 30 days for confirmed issues. Credit is given in the advisory unless you
prefer otherwise.

## Scope and deployment assumptions

Tesla Charger Monitoring is designed for **LAN-only** use. Exposing it to the
internet (port-forwarding) is unsupported. The Wall Connector's own local API
is unauthenticated plain HTTP; that is a property of the device, not of this
project, and is out of scope.

## Supply chain

Release images will be signed with cosign (keyless) and ship SBOM and SLSA
provenance attestations; verification instructions will be in the release
notes.
