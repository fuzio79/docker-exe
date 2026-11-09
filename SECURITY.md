# Security Policy

## What this software is, security-wise

`docker-exec` mounts `/var/run/docker.sock`. That socket is **root on the host**:
anyone who can talk to it can start a privileged container, mount the host
filesystem, and take the machine. `POST /docker/exec/{name}` is therefore an
arbitrary-command-as-root primitive, wrapped in a trust check.

Treat a bug in the trust check as a **host compromise**, not an information
disclosure. The same goes for anything that lets a caller reach a container whose
environment holds credentials — `env` is a valid command, so "readable by exec" and
"readable" are the same thing.

## Supported versions

Only the latest release receives fixes. There are no maintenance branches.

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.2   | No — before 1.2.0, `managed=true` was a self-asserted label and *anyone* who could `docker run` on the host could obtain exec access. Upgrade. |

## Reporting a vulnerability

Please report privately, not in a public issue:

- Open a **private** security advisory on the GitHub repository, or
- Contact the maintainer directly (see the repository profile).

Include the version, a description, and ideally a minimal reproduction. A PoC
that reaches host root is welcome and will be treated as urgent.

**Do not** include real credentials or host-specific secrets in a report.

What to expect:

- Acknowledgement within a few days.
- An assessment of severity and a fix timeline.
- Credit in the release notes, unless you prefer otherwise.

## Known and accepted limitations

These are design decisions, documented in the README, and are **not**
vulnerabilities. Please do not report them as such:

1. **The API is HTTP-only.** The service does not terminate TLS. Sending
   `X-API-Key` across an untrusted network exposes it; run it behind a TLS
   reverse proxy, or keep it on a trusted segment.
2. **`DOCKER_EXEC_ALLOWLIST` is name-based.** Anyone who can already `docker run`
   on the host can create a container with a listed name and be trusted. This is
   accepted: such a person is already root. The allowlist guards against
   *accident and drift*, not a hostile local user.
3. **A valid signature is bound to one container creation.** Recreating a
   container invalidates its signature and the container starts returning 403.
4. **`/docs` and `/openapi.json` are unauthenticated.** They expose the API
   schema, not the containers. Disable them if your threat model dislikes that.
5. **A timed-out command may survive the request.** The Engine API has no
   exec-kill endpoint; enforcement relies on a `timeout` binary inside the target
   container. Where that binary is missing, `timeout_enforced: false` is reported.

## Hardening checklist for operators

- Set `DOCKER_EXEC_API_KEY` to a long random value; it is also the default signing
  key. Rotating it invalidates every existing signature.
- Prefer signed mode over the allowlist, and keep the allowlist temporary.
- Do not add a container to the allowlist if its environment holds credentials the
  API caller should not see.
- Bind to a specific interface or front it with TLS; do not expose 8091 to an
  untrusted network.
- Keep `mem_limit` set — an unbounded exec can consume host memory.
