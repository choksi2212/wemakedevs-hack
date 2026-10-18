# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for anything security-sensitive. Use GitHub's
private vulnerability reporting instead:

<https://github.com/choksi2212/wemakedevs-hack/security/advisories/new>

Please include reproduction steps and the URL/commit you tested. We will
acknowledge reports and respond as fast as a volunteer project can.

## What this project is

SEVER is a **judge-facing hackathon demo** — an attack-path interdiction
console over identity graphs on FalkorDB. It is demo software: the console
has **no authentication layer by design** (judges must walk in with zero
friction), and it is deployed on a free tier that spins down when idle. Do not
expose it to untrusted networks or point it at production identity data.

## Known, deliberate posture (not vulnerabilities — read before reporting)

| Surface | Posture | Why |
|---|---|---|
| Console HTTP API (`/api/*`) | No auth | Judge-facing demo; anyone who can reach the deployment can read/mutate the demo graph. Run it on a private host if that matters. |
| FastAPI docs (`/docs`, `/redoc`) | Off by default (`SEVER_DOCS` unset) | Rendered OpenAPI schema is attacker recon on a public deploy; enable locally for development. |
| Local `docker compose up` engine | FalkorDB RESP has **no auth by default**; the compose file binds `6379` and `3000` on all interfaces | Only safe on an isolated demo box. On any shared host bind loopback (`127.0.0.1:6379:6379`) or firewall the ports — see the SECURITY NOTE in `docker-compose.yml`. |
| Live deployment engine | FalkorDB Cloud (managed) — credentials only on the free tier (**no TLS**; the Render→engine leg is plaintext RESP, documented in README §6/§11); TLS requires the paid Startup tier or self-hosting on localhost/private networking | `SEVER_FALKOR_PASSWORD` is a Render dashboard secret (`sync: false` in `render.yaml`); the credential never appears in the repo. |
| `/api/health` | Unauthenticated, one cheap engine query, writes no receipt | The only probe cheap enough for Render's 5s health-check window (see `render.yaml`). |
| Secrets handling | `.env*` (except `.env.example`), `.secrets/`, `*.key` are gitignored | `.env.example` documents every variable with empty values; real values live only in the environment or the deploy dashboard. |

## Hygiene commitments

- No credentials, tokens, or personal data are committed to this repository;
  the sample estate is SpecterOps' Apache-2.0 BloodHound CE synthetic data.
- Engine credentials are injected at runtime (`render.yaml` `sync: false`),
  never baked into the Docker image.
- The Docker image runs the console as installed from `pyproject.toml`; it
  downloads the public sample data at build time and nothing else.
