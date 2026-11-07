# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 1.2.0 predate this file and are summarised from the code history
rather than reconstructed in full.

## [Unreleased]

## [1.2.2]

Documentation, packaging and three correctness fixes. No change to the trust
model.

### Fixed

- **`/health` leaked the internal Docker exception** in its 503 body. It is the
  only unauthenticated endpoint, so it now logs the detail server-side and returns
  a fixed message; `detail` no longer reflects daemon state to an unauthenticated
  caller.
- **`stdout_truncated` / `stderr_truncated` were always `false` on the exec path.**
  The stream loop stored at most `MAX_OUTPUT_BYTES`, and the flags were then
  derived by comparing that already-capped buffer against the same cap — so they
  could never be true. Truncation is now recorded from the byte counters, which
  count everything read, while the buffers remain capped. `bytes_total_*` is
  unchanged and remains the honest counter.
- **The exec loop kept reading after both output buffers were full**, discarding
  every further frame until the wall-clock deadline. Memory was already bounded,
  but a `yes`-style command still burned socket and CPU time for up to the full
  timeout, holding a worker slot. The loop now stops at a read budget
  (`MAX_OUTPUT_BYTES × EXEC_READ_BUDGET_FACTOR`, default 4) and reports
  `stream_stopped_early: true` so callers know `bytes_total_*` is a lower bound.
- **`_TIMEOUT_CAPABLE` grew without bound.** It was keyed by container ID, which
  changes on every recreation, so the cache retained a dead entry per container
  ever probed — a slow leak in a long-lived process. Now an LRU capped at 256
  entries.
- `docker-compose.yml` used the legacy top-level `mem_limit` key; now the
  Compose-spec `deploy.resources.limits.memory`.
- The deploy workflow cloned `apps/docker-exe.git`, which only worked via a 301
  redirect left over from the repository migration. It now uses the canonical
  `LLM/docker-exe.git`.

### Changed

- README documents the **consequences of signing**: the signature is bound to a
  single container creation; rotating the API key silently invalidates every
  signature (the signing key falls back to it); allowlisting a signed container
  silently downgrades it to name-based trust; and a `403` after signing usually
  means the container was recreated.
- The compose allowlist comment now names the credentials actually reachable
  through `/docker/exec` for each listed container, not just one of them.
- `Dockerfile` documents that GID 984 is the host's docker-socket group and how
  to find your own.

### Added

- `LICENSE` (MIT).
- `SECURITY.md` — disclosure policy plus the accepted limitations, so they are
  not re-reported as vulnerabilities.
- `.gitignore` (with an explicit `.env` guard) and `.dockerignore` (keeps `.git`
  and `.gitea` out of the build context).
- `tests/` — the trust model (signed / allowlisted / forged / re-created), the
  truncation and read-budget behaviour, the bounded probe cache, and `/health`
  non-disclosure. No test contacts a Docker daemon.
- `requirements-dev.txt`.
- `.gitea/workflows/public-sync.yml` — manual (`workflow_dispatch` only) publish
  to the public GitHub mirror. Same pattern as `LLM/rag-middleware`: a curated
  `git archive` snapshot (so `.gitea/` is never published), a `gitleaks` scan, an
  internal-identifier check, and an explicit `confirm=PUBLISH` for real pushes.
  Uses the existing org secret `OCG_GITHUB_PAT`.
- `.gitea/workflows/ci.yml` — runs the test suite and four publication guards on
  every push: `py_compile`, version/changelog agreement, no internal identifiers
  in the exportable tree, and a check that `public-sync` uses `OCG_GITHUB_PAT`.
- `.gitattributes` — `export-ignore` rules for the snapshot.

## [1.2.1]

### Fixed

- **The `timeout` capability probe called `exec_run` on `APIClient`**, which does
  not define it. The resulting `AttributeError` was swallowed by a bare
  `except Exception`, so every container was reported as having no `timeout`
  binary and **timeout enforcement was silently off fleet-wide**. The probe now
  goes through the container object, and a failed probe is logged rather than
  silently concluding "no wrapper".

## [1.2.0]

The trust model was rewritten; this is the release that makes the service
defensible to expose.

### Security

- **`managed=true` was self-asserted and therefore meaningless.** Labels live in
  the container's own `Config`, so anyone able to `docker run` on the host could
  mint one and obtain RCE as root through `/docker/exec`. Trust now requires
  `managed=true` **and** `managed.signature = hmac_sha256(key, container_id)`,
  compared with `hmac.compare_digest`.
- `DOCKER_EXEC_ALLOWLIST` added as an explicitly-temporary migration path for
  containers that are already managed but unsigned. It is documented as *not*
  closing the name-spoofing hole.
- `PROTECTED_CONTAINERS` is now enforced by **name**, so a re-created container
  cannot re-mint an exemption through a label.

### Fixed

- **Output was buffered in full before truncation.** `exec_run(demux=True)`
  concatenated every frame, so `yes` allocated 34 GB in two seconds while the
  service ran with no cgroup limit. Output is now streamed and capped as it
  arrives, and the container has a memory limit.
- **Commands could be executed twice.** A 126/127 exit whose output merely
  contained the string "timeout" (or any unmatched `APIError`) triggered a second,
  unwrapped run — so commands with side effects ran twice. Capability is now
  probed once and cached; nothing is ever re-executed.
- Lifecycle errors were flattened to `500`. `_api_error_to_http` maps the real
  status and explanation; `NotFound` is tested before `APIError` because
  `ImageNotFound` subclasses it and the reverse order swallows every 404.
- `c.image.tags` issued an extra `images.get()` per container and raised
  `ImageNotFound` for removed or retagged images, aborting the whole `/docker/ps`
  listing.
- Stopped containers were invisible everywhere. `/docker/ps` gained `?all=true`
  and `POST /docker/start/{name}` was added — without it a stopped container could
  never be brought back.
- Compose interpolated a missing `DOCKER_EXEC_API_KEY` to an empty string, which
  `restart: unless-stopped` turned into a crash loop. Now `${VAR:?...}` fails
  immediately and legibly.

### Added

- `/docker/start`, `?all=true` on `/docker/ps`, `bytes_total_out`,
  `bytes_total_err`, `timeout_enforced`, `duration_s` in exec responses.
- Healthcheck on `/health`, a memory limit, and a `py_compile` gate in CI before
  the running service is replaced.
- Deploy with `compose up --wait`: a crash loop no longer reports as a green
  deploy. Rollback to the previous image when the new one is not healthy.

### Changed

- A timed-out command no longer returns `504`. It returns a normal result with
  `timed_out: true` and the wrapper's exit code (`124`/`137`).
- **Existing `managed=true` containers stop working until signed or allowlisted.**
  Deliberate: this is the security fix.

## [1.1.0]

### Added

- Container lifecycle endpoints (`restart`, `stop`, `rm`), `/docker/logs`,
  `/docker/stats`, `/docker/ps`.
- `timeout -s KILL` wrapper around exec, and `MANAGED_LABEL` filtering.
