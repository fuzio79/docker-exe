# docker-exec

Minimal Docker container management service that exposes a small REST API for
Open WebUI tools.

> **Read this before deploying.** This service mounts the Docker socket. Being a
> member of the socket's group — or simply having access to it — is effectively
> **root on the host**, so `POST /docker/exec/{name}` is an
> arbitrary-command-as-root primitive. That is the whole point of the service, and
> it is why trust is explicit and narrow. See [SECURITY.md](SECURITY.md).

## Trust model (read this first)

This service mounts the host Docker socket, so `/docker/exec/{name}` is
effectively **root on the host** for any container it accepts. Trust is therefore
explicit: a container is only ever touched if it is *trusted*, and the
`managed=true` label **on its own is not enough**. Labels live in the container's
own `Config`, so anyone able to `docker run` on this host could otherwise mint
`managed=true` and walk in.

A container is trusted if **either**:

1. its **name** is listed in `DOCKER_EXEC_ALLOWLIST` (plus the `managed=true`
   label), or
2. it carries `managed=true` **and** a valid
   `managed.signature = hmac_sha256(key, container_id)`.

### Current mode: allowlist by name

This deployment runs in **allowlist mode**. `docker-compose.yml` sets:

```
DOCKER_EXEC_ALLOWLIST=open-webui,crawl4ai,rag-service,gitea-runner,gitea-runner-2,gitea-runner-3,openwebui-companion
```

All of them also carry `managed=true`. Nothing else is reachable — `docker-exec`
itself is `managed=false`, and any container not in that list gets `403`.

**Accepted trade-off, stated plainly:** name-based trust does *not* close the
spoofing hole. Someone who can already `docker run` on this host can create a
container called e.g. `crawl4ai`, and it will be trusted. That is judged
acceptable here because anyone with `docker run` on this host is already
effectively root — the allowlist is a guard against *accident and drift*, not
against a hostile local user. If that assumption ever changes, move to signed
mode below.

`docker ps` is not a boundary either: the allowlist is matched against the
container's name, so keep the names accurate and do not reuse them for
throwaway containers.

**Every listed container's environment becomes readable** to any holder of the
API key, because `env` is a valid command. Before adding a name, ask what
credentials that container carries. The compose file spells out what the current
list exposes.

### Changing the trusted set

Edit the list and redeploy (or set the env var directly):

```bash
# add a container to the trusted set
DOCKER_EXEC_ALLOWLIST=open-webui,crawl4ai,rag-service,gitea-runner,gitea-runner-2,gitea-runner-3,my-new-service
```

A container must still carry `managed=true` to be accepted. To stop managing a
container, drop it from the list and make sure it does not have the label.

`PROTECTED_CONTAINERS` (default `docker-exec`) is enforced by **name** and is
independent of the allowlist, so `docker-exec` cannot be stopped, restarted or
removed through this API even if a container reuses the name.

### Signed mode (available, not currently used)

If you ever want trust that cannot be forged by whoever creates the container,
switch to signatures. Mint one from the host after the container exists (the ID
only exists then):

```bash
KEY="$DOCKER_EXEC_SIGNING_KEY"        # falls back to DOCKER_EXEC_API_KEY
CID=$(docker inspect -f '{{.Id}}' mycontainer)   # FULL 64-char id, not the short one
SIG=$(printf '%s' "$CID" | openssl dgst -sha256 -hmac "$KEY" -r | cut -d' ' -f1)
docker update \
  --label-add managed=true \
  --label-add managed.signature="$SIG" \
  mycontainer
```

Then remove the name from `DOCKER_EXEC_ALLOWLIST` and redeploy, so the
signature becomes authoritative.

## Consequences of signing

Signing is the stronger option, but it has costs that are easy to discover at the
worst possible moment. All of them are real:

### 1. The signature is bound to one container creation, not to the image or name

`container_id` changes whenever the container is recreated, so:

| Operation | Container ID | Signature |
|---|---|---|
| `docker update` (labels, memory, cpus, restart policy) | unchanged | still valid |
| `docker restart` / `stop` / `start` / `rename` | unchanged | still valid |
| `docker compose up` after editing the stack (image/env/ports/volumes/labels) | **new** | **must be re-signed** |
| `docker compose down && up`, `--force-recreate`, `docker rm` + `docker run` | **new** | **must be re-signed** |
| Watchtower / pull-and-recreate | **new** | **must be re-signed** |

The signature also cannot be pre-set in `docker-compose.yml`, because the
container ID does not exist until after creation.

**This is the main reason the deployment uses the allowlist**: those containers
are recreated on every stack edit or image update, and a re-sign-per-recreate
workflow breaks them *silently* with a `403` unless you hook the signing step
into whatever recreates them.

If you want forgery-proof trust *and* frequent recreation, sign over something
stable instead of the container ID — e.g. the image digest
(`hmac(key, sha256(image_id))`) or `compose project + service` — and accept that
any container built from a signed image is then trusted. That is a change to
`is_trusted` and `_sign` in `main.py`; it has **not** been implemented.

### 2. Rotating the API key silently invalidates every signature

`DOCKER_EXEC_SIGNING_KEY` **falls back to `DOCKER_EXEC_API_KEY`** when unset, and
that is the default configuration. So:

- rotating `DOCKER_EXEC_API_KEY` also changes the signing key, and
- **every signed container immediately starts returning `403`.**

There is no warning and no grace period — the containers just stop being
manageable. Either set `DOCKER_EXEC_SIGNING_KEY` to a *separate* secret before
enabling signed mode, or treat the API key as a signing secret that requires
re-signing every container after each rotation.

### 3. Allowlisting a signed container silently downgrades it

`is_trusted` checks the allowlist **before** the signature. A container whose
name is in the allowlist is accepted by name, and its signature is never
consulted. Signing only takes effect once the name is removed from the list.

The practical consequence: if you sign everything and then add one name back to
the allowlist to debug something, that container is no longer protected by its
signature — and nothing tells you. **Remove the name, don't add it back.**

### 4. A `403` after signing usually means "recreated", not "misconfigured"

Because of (1), the most common cause of a container suddenly being rejected is
that it was recreated and needs re-signing. Check the container ID against the
one the signature was minted for before debugging the key.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`    | `/docker/ps` | List trusted containers (`?all=true` includes stopped ones) |
| `GET`    | `/docker/stats` | CPU / memory / disk / network usage (all, or one via `?name=`) |
| `GET`    | `/docker/logs/{name}` | Tail recent logs (`?lines=200`) |
| `POST`   | `/docker/exec/{name}` | Run a single command inside a container and return its output |
| `POST`   | `/docker/start/{name}` | Start a stopped trusted container |
| `POST`   | `/docker/restart/{name}` | Restart a trusted container |
| `POST`   | `/docker/stop/{name}` | Stop a trusted container |
| `DELETE` | `/docker/rm/{name}` | Remove a trusted container (`?force=true`) |
| `GET`    | `/health` | Service + Docker socket health check |

Errors are passed through from Docker rather than flattened to `500`: `404` for
an unknown container, `403` for an untrusted or protected one, `409` where Docker
refuses (for example removing a running container without `force`).

`/health` is deliberately **unauthenticated** (the container healthcheck cannot
send a key) and therefore returns a fixed message rather than the underlying
Docker error. `/docs` and `/openapi.json` are currently also unauthenticated.

## Running a single command inside a container

`POST /docker/exec/{name}` runs one command in the target container and returns
its exit code plus separated stdout / stderr.

The command is sent as an **argv list** straight to the Docker exec API — *not*
through a shell — so shell metacharacters cannot be injected.

Request body:

```json
{
  "cmd": ["curl", "-s", "https://example.com"],
  "workdir": null,
  "user": null,
  "timeout": 30
}
```

- `cmd` — **required**, non-empty argv list (e.g. `["curl", "-s", "https://example.com"]`)
- `workdir` — optional working directory inside the container
- `user` — optional user to run as
- `timeout` — max seconds before the command is killed (default `30`, max `600`)

Response:

```json
{
  "name": "mycontainer",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "stdout_truncated": false,
  "stderr_truncated": false,
  "bytes_total_out": 1256,
  "bytes_total_err": 0,
  "timed_out": false,
  "timeout_enforced": true,
  "stream_stopped_early": false,
  "duration_s": 0.31
}
```

`bytes_total_out` / `bytes_total_err` count everything the command produced, so
`stdout_truncated: true` combined with a large `bytes_total_out` tells the caller
how much was dropped. The cap applies to bytes.
`stream_stopped_early: true` means the read budget (below) was exhausted, so
`bytes_total_*` are a lower bound rather than the complete total.

### Timeouts and output limits

Output is **streamed and capped while it arrives**. It is never buffered in full
first: this service had no memory limit, and a single `yes` allocated 34 GB in
two seconds.

Two independent limits stop the read loop:

- the **wall-clock deadline** (`timeout` + 5s grace), and
- a **read budget** of `MAX_OUTPUT_BYTES × EXEC_READ_BUDGET_FACTOR` (default
  `65536 × 4`). Once that much has been read, the stream is detached — there is
  nothing more it can store, so continuing to read only burns socket time and
  CPU. This is what stops a `yes`-style command from occupying a worker for the
  full timeout.

Killing a timed-out command uses a `timeout -s KILL` wrapper inside the
container, because the Docker API has no exec-kill endpoint — detaching the
stream leaves the process running. Availability of that wrapper is probed once
per container (`timeout --help`, which works on GNU and BusyBox alike) and
cached in a bounded LRU:

- `timeout_enforced: true` — the command is killed at the deadline and
  `timed_out` comes from the wrapper's own exit code (`124`/`137`), not a guess.
- `timeout_enforced: false` — the container has no `timeout` binary. The request
  still returns at the deadline with `timed_out: true`, but the process may keep
  running inside the container.

A command is never re-executed, so writing commands are safe to retry.

## Deployment

Deployed via `docker compose`. The service mounts the host Docker socket, is
memory-capped, labelled `managed=false`, and has a healthcheck on `/health`.

`DOCKER_EXEC_API_KEY` is required and `docker-compose.yml` uses
`${DOCKER_EXEC_API_KEY:?...}`, so `docker compose up` fails immediately when the
secret is missing instead of crash-looping.

The image runs as a non-root user in the host's **docker group** (GID `984` in
this deployment). That group owns `/var/run/docker.sock`; the numeric GID is
host-specific and documented in the `Dockerfile`.

The Gitea workflow `.gitea/workflows/deploy.yml` builds and redeploys on every
push to `main`:

1. **Syntax check** — `py_compile` on `main.py` in a throwaway container, before
   the running service is touched.
2. **Build** — `docker build --no-cache`, so a stale image is never reused.
3. **Deploy** — `docker compose up -d --build --wait --wait-timeout 180`. The
   step fails unless the new container reports `healthy`.
4. **Rollback** — if the deploy is not healthy, the job prints `docker ps -a`
   plus the last 50 log lines and then restarts the **previous image** (same
   ports, volumes, socket mount and env) and verifies *that* is healthy. The job
   still fails, so the failure is visible, but the service is not left down.

The rollback's `docker run` mirrors `docker-compose.yml`; if the compose service
changes, update the rollback to match.

Publishing to the public GitHub mirror is a **separate, manual** workflow
(`.gitea/workflows/public-sync.yml`, `workflow_dispatch` only). It builds a
*curated snapshot* with `git archive`, which honours `.gitattributes`, so
`.gitea/` never leaves this instance. The snapshot is then scanned with
`gitleaks`, checked for internal identifiers, and only pushed when
`confirm=PUBLISH` is supplied. Nothing is published on a merge.

Two things the workflow learned the hard way, worth keeping in mind when editing
it: the `run:` blocks are parsed by **dash**, not bash (`sh -n` every step before
committing), and `docker run -v /src:/src` inside a job mounts a **host** path,
not the job container's.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

The tests cover the trust model (signed / allowlisted / forged / re-created),
the truncation and read-budget behaviour, the bounded probe cache and the
`/health` non-disclosure. They use fakes and **never** contact a Docker daemon.

## License

MIT — see [LICENSE](LICENSE). The warranty disclaimer is not decorative here: run
this with the wrong trust configuration and it will hand host root to whoever can
reach it.
